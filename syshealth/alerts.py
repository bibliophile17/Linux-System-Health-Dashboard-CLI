"""Alert evaluation with state tracking.

An alert is identified by (metric, target), e.g. ("disk_percent", "/data").
Events are emitted only on *transitions*, so a condition that stays bad produces
one "opened" event, not one per refresh.

Missing data is not good news: when a metric cannot be read, existing alerts for
it keep their state instead of being resolved.
"""

from __future__ import annotations

import datetime
import json
import os
from dataclasses import dataclass
from typing import Optional

from .collectors import Snapshot
from .config import Config

RANK = {"ok": 0, "warning": 1, "critical": 2}
NAMES = ("ok", "warning", "critical")


def iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Observation:
    metric: str
    target: str
    value: float


def classify(value: float, warn: float, crit: float) -> str:
    return "critical" if value >= crit else "warning" if value >= warn else "ok"


def observations(snap: Snapshot) -> tuple[list[Observation], set[str]]:
    """Return readable observations and the set of metrics whose source was readable."""
    obs: list[Observation] = []
    readable: set[str] = set()
    if snap.cpu_percent is not None:
        readable.add("cpu_percent")
        obs.append(Observation("cpu_percent", "host", snap.cpu_percent))
    if snap.memory is not None:
        if snap.memory.percent is not None:
            readable.add("memory_percent")
            obs.append(Observation("memory_percent", "host", snap.memory.percent))
        if snap.memory.swap_percent is not None:
            readable.add("swap_percent")
            obs.append(Observation("swap_percent", "host", snap.memory.swap_percent))
    if snap.disks is not None:
        readable.add("disk_percent")
        obs += [Observation("disk_percent", d.mount, d.percent) for d in snap.disks]
    if snap.loadavg is not None and snap.cpu_count:
        readable.add("load_per_core")
        obs.append(Observation("load_per_core", "host", snap.loadavg[0] / snap.cpu_count))
    if snap.process_count is not None:
        readable.add("process_count")
        obs.append(Observation("process_count", "host", float(snap.process_count)))
    return obs, readable


def _key(metric: str, target: str) -> str:
    return f"{metric}|{target}"


class AlertEngine:
    def __init__(self, cfg: Config, state: Optional[dict] = None):
        self.cfg = cfg
        self.state: dict[str, dict] = self._sanitize(state or {})

    @staticmethod
    def _sanitize(state: dict) -> dict:
        """Accept only well-formed entries from a persisted state file."""
        good = {}
        for k, v in state.items():
            if (isinstance(v, dict) and v.get("severity") in ("warning", "critical")
                    and isinstance(v.get("metric"), str) and isinstance(v.get("target"), str)
                    and isinstance(v.get("since"), str)):
                good[k] = v
        return good

    def evaluate(self, snap: Snapshot) -> list[dict]:
        obs, readable = observations(snap)
        now = iso(snap.timestamp)
        events: list[dict] = []
        seen: set[str] = set()
        h = self.cfg.hysteresis

        for o in obs:
            warn, crit = self.cfg.thresholds[o.metric]
            key = _key(o.metric, o.target)
            seen.add(key)
            cur = self.state.get(key)
            cur_sev = cur["severity"] if cur else "ok"
            new_sev = classify(o.value, warn, crit)
            if RANK[new_sev] < RANK[cur_sev]:
                relaxed = classify(o.value, warn * (1 - h), crit * (1 - h))
                new_sev = NAMES[min(RANK[cur_sev], RANK[relaxed])]
            if new_sev == cur_sev:
                if cur:
                    cur["value"], cur["updated"] = o.value, now
                continue
            threshold = crit if new_sev == "critical" else warn
            if new_sev == "ok":
                events.append(self._event("resolved", o.metric, o.target, "ok", cur_sev, o.value, warn, now))
                del self.state[key]
            else:
                kind = ("opened" if cur is None else
                        "escalated" if RANK[new_sev] > RANK[cur_sev] else "deescalated")
                events.append(self._event(kind, o.metric, o.target, new_sev, cur_sev, o.value, threshold, now))
                self.state[key] = {"metric": o.metric, "target": o.target, "severity": new_sev,
                                   "since": cur["since"] if cur else now, "value": o.value,
                                   "threshold": threshold, "updated": now}

        # Alerts whose metric is readable but whose target vanished (e.g. unmounted disk).
        for key in [k for k, v in self.state.items() if k not in seen and v["metric"] in readable]:
            v = self.state.pop(key)
            events.append(self._event("resolved", v["metric"], v["target"], "ok", v["severity"],
                                      None, v.get("threshold"), now, reason="target no longer present"))
        return events

    @staticmethod
    def _event(kind, metric, target, sev, prev, value, threshold, ts, reason=None) -> dict:
        ev = {"time": ts, "event": kind, "severity": sev, "previous_severity": prev,
              "metric": metric, "target": target, "value": value, "threshold": threshold}
        if reason:
            ev["reason"] = reason
        return ev

    @property
    def active(self) -> list[dict]:
        return sorted(self.state.values(), key=lambda a: (-RANK[a["severity"]], a["metric"], a["target"]))

    @property
    def worst(self) -> str:
        return max((a["severity"] for a in self.state.values()), key=RANK.__getitem__, default="ok")


# ------------------------------------------------------------ persistence ----

def load_state(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}                  # first run, unreadable or corrupt: start clean


def save_state(path: str, state: dict) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)          # atomic: readers never see a half-written file


def append_log(path: str, events: list[dict]) -> None:
    if events:
        with open(path, "a", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, sort_keys=True) + "\n")
