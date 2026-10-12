"""JSON export of snapshots and alert state."""

from __future__ import annotations

import dataclasses
import json
from typing import Optional

from .alerts import AlertEngine, iso
from .collectors import Snapshot
from .config import Config

SCHEMA_VERSION = 1


def snapshot_dict(snap: Snapshot) -> dict:
    d = dataclasses.asdict(snap)
    d["timestamp_iso"] = iso(snap.timestamp)
    return d


def report_dict(snap: Snapshot, engine: AlertEngine, events: list[dict], cfg: Config,
                findings: Optional[list] = None) -> dict:
    doc = {
        "schema_version": SCHEMA_VERSION,
        "status": engine.worst,
        "snapshot": snapshot_dict(snap),
        "alerts": {"active": engine.active, "events": events},
        "thresholds": {m: {"warn": w, "crit": c} for m, (w, c) in cfg.thresholds.items()},
    }
    if findings is not None:
        doc["findings"] = [dataclasses.asdict(f) for f in findings]
    return doc


def dumps(obj: dict, pretty: bool = True) -> str:
    return json.dumps(obj, indent=2 if pretty else None, sort_keys=True, allow_nan=False)
