"""JSON incident reports.

Reports are a pure function of their inputs (no wall-clock reads, sorted keys), so the same
evidence always yields byte-identical JSON. Privacy: only process *names* are collected (never
command lines or environment); journal lines are opt-in and redacted.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
from typing import Optional

from .alerts import AlertEngine, iso
from .config import Config
from .diagnostics import RANK, Finding, highest
from .evidence import Evidence
from .export import snapshot_dict

INCIDENT_SCHEMA = 1
PRIVACY_NOTE = ("Contains hostname, kernel version, process names and resource figures. Does not contain command "
                "lines, environment variables, file contents or credentials. Log lines are included only when "
                "explicitly requested and are redacted on a best-effort basis; review before sharing.")


def build_incident(ev: Evidence, findings: list[Finding], engine: AlertEngine, cfg: Config,
                   log_lines: Optional[list[str]] = None, logs_requested: bool = False) -> dict:
    snap = ev.snap
    problems = [f for f in findings if RANK[f.status] > 0]
    unknown = [f.id for f in findings if f.status == "unknown"]
    counts = {s: sum(1 for f in findings if f.status == s) for s in ("critical", "warning", "info", "ok", "unknown")}
    status = highest(findings)
    if problems:
        headline = (f"{status} - " + ", ".join(f"{f.id} ({f.status})" for f in
                                               sorted(problems, key=lambda f: (-RANK[f.status], f.id))))
    else:
        headline = "No issues detected by the checks that could run"
    ident = hashlib.sha256(f"{iso(snap.timestamp)}|{snap.hostname}|{headline}".encode()).hexdigest()[:12]
    return {
        "schema_version": INCIDENT_SCHEMA,
        "incident_id": f"inc-{ident}",
        "generated_at": iso(snap.timestamp),
        "host": {"hostname": snap.hostname, "kernel": snap.kernel},
        "summary": {"status": status, "headline": headline, "counts": counts, "not_assessed": sorted(unknown)},
        "alerts": {"active": engine.active},
        "findings": [dataclasses.asdict(f) for f in sorted(problems, key=lambda f: (-RANK[f.status], f.id))],
        "snapshot": snapshot_dict(snap),
        "collection": {"unavailable_metrics": sorted(snap.unavailable), "commands_run": ev.commands_run,
                       "thresholds": {m: {"warn": w, "crit": c} for m, (w, c) in sorted(cfg.thresholds.items())}},
        "logs": ({"source": "journalctl -p err (redacted)", "available": log_lines is not None,
                  "lines": log_lines or []} if logs_requested else None),
        "privacy_note": PRIVACY_NOTE,
    }


def write_exclusive(path: str, text: str, force: bool = False) -> None:
    """Create ``path`` without clobbering an existing file unless ``force``."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(path, flags, 0o600)           # owner-only: reports may be sensitive
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
        if not text.endswith("\n"):
            fh.write("\n")
