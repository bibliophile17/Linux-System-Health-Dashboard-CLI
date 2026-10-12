"""Reproducible evaluation of the incident analysis against the frozen synthetic dataset.

    python -m syshealth.analysis_eval                       # all splits
    python -m syshealth.analysis_eval --split dev -v        # development cases, with per-case detail
    python -m syshealth.analysis_eval --json eval/results.json

Metric definitions live in docs/analysis-evaluation.md and were fixed before this ran. The synthetic dataset is
small and written by the rule author: the numbers measure consistency and abstention behaviour, not real-world
accuracy.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import sys
from typing import Optional

from .analysis import CAUSE_TITLES, CONF_RANK, FINDING_FOR, PRIORITY, Analysis, RankedCause, analyze
from .collectors import DiskUsage, Memory, NetIface, ProcInfo, Snapshot
from .config import Config
from .diagnostics import RANK, Finding, run_diagnostics
from .evidence import DiskIORate, Evidence, Listener, Pressure, SocketSummary

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_DATASET = ROOT / "eval" / "incidents.json"
FIXED_TS = 1_800_000_000.0
DEFINITE = {"diagnosed", "multiple_issues"}
ABSTAIN = {"inconclusive", "insufficient_data"}
GIB = 2**30


# ------------------------------------------------------------- dataset ------


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_dataset(path: pathlib.Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def evidence_from_spec(spec: dict) -> Evidence:
    """Build an Evidence from a dataset spec. `None` means the metric was unreadable."""
    mem = None
    if spec.get("memory") is not None:
        m = spec["memory"]
        total = int(m["total_gib"] * GIB)
        used = int(total * m["used_percent"] / 100)
        s_total = int(m["swap_total_gib"] * GIB)
        s_pct = m["swap_used_percent"]
        mem = Memory(
            total,
            total - used,
            used,
            m["used_percent"],
            s_total,
            int(s_total * s_pct / 100),
            s_pct if s_total > 0 else None,
        )
    disks = (
        None
        if spec.get("disks") is None
        else [
            DiskUsage(
                d["mount"],
                d["fstype"],
                100 * GIB,
                int(d["percent"] * GIB),
                int((100 - d["percent"]) * GIB),
                float(d["percent"]),
            )
            for d in spec["disks"]
        ]
    )
    net = (
        None
        if spec.get("net") is None
        else [NetIface(n["name"], 0, 0, n["errors_total"], n["drops_total"], 0, 0, 0, 0) for n in spec["net"]]
    )

    def procs(key):
        return [ProcInfo(p["pid"], p["name"], p["cpu_percent"], p["mem_percent"]) for p in spec.get(key) or []]

    load = None if spec.get("loadavg") is None else tuple(spec["loadavg"])
    snap = Snapshot(
        timestamp=FIXED_TS,
        hostname="synthetic",
        kernel="Linux synthetic",
        interval=1.0,
        cpu_percent=spec.get("cpu_percent"),
        cpu_per_core=[],
        cpu_count=spec.get("cpu_count"),
        loadavg=load,
        uptime_seconds=spec.get("uptime_seconds"),
        memory=mem,
        disks=disks,
        network=net,
        process_count=spec.get("process_count"),
        top_cpu=procs("top_cpu"),
        top_mem=procs("top_mem"),
    )
    for name in ("cpu_percent", "loadavg", "uptime_seconds", "memory", "disks", "network", "process_count"):
        if getattr(snap, name) is None:
            snap.unavailable.append(name)

    diskio = (
        None
        if spec.get("diskio") is None
        else [DiskIORate(d["device"], d["util_percent"], 0.0, 0.0, 0.0, d.get("await_ms")) for d in spec["diskio"]]
    )
    sockets = (
        None
        if spec.get("sockets") is None
        else SocketSummary([Listener(a, p) for a, p in spec["sockets"]["listeners"]], dict(spec["sockets"]["states"]))
    )
    pressure = (
        None if spec.get("pressure") is None else {res: Pressure(v[0], v[1]) for res, v in spec["pressure"].items()}
    )
    return Evidence(
        snap,
        diskio,
        sockets,
        pressure,
        spec.get("oom_kills"),
        spec.get("failed_units"),
        spec.get("net_deltas"),
        bool(spec.get("commands_run", False)),
    )


# ------------------------------------------------------------ analyzers -----


def naive_analyze(findings: list[Finding]) -> Analysis:
    """Comparison baseline: what `diagnose` already offers, ranked by severity only.

    No corroboration, no contradiction handling, no abstention: every warning/critical finding becomes an
    asserted cause (critical -> strong, warning -> moderate).
    """
    inverse = {v: k for k, v in FINDING_FOR.items()}
    causes = []
    for f in findings:
        if f.status in ("warning", "critical") and f.id in inverse:
            cause = inverse[f.id]
            causes.append(
                RankedCause(
                    cause,
                    CAUSE_TITLES[cause],
                    "strong" if f.status == "critical" else "moderate",
                    RANK[f.status],
                    list(f.observations),
                )
            )
    causes.sort(key=lambda c: (-c.points, PRIORITY.index(c.cause)))
    obs = [o for c in causes for o in c.supporting]
    status = "healthy" if not causes else "multiple_issues" if len(causes) > 1 else "diagnosed"
    return Analysis(status, "severity-only ranking", causes, obs, ["(naive baseline: no uncertainty modelling)"], [])


# --------------------------------------------------------------- scoring ----


def _caused(a: Analysis) -> list[str]:
    return [c.cause for c in a.causes]


def evaluate_case(case: dict, a: Analysis) -> dict:
    exp = case["expected"]
    top = a.causes[0] if a.causes else None
    asserted = [c for c in a.causes if CONF_RANK[c.confidence] >= CONF_RANK["moderate"]]
    unsupported = [c.cause for c in asserted if c.cause not in exp["valid_causes"]]
    traceable = all(s in a.observations for c in a.causes for s in c.supporting)
    text = " ".join(a.uncertainties).lower()
    flags = {
        "status_match": a.status == exp["status"],
        "top1": top is not None and top.cause in exp["acceptable_primary"],
        "top3": set(exp["required_in_top3"]) <= set(_caused(a)[:3]),
        "abstained": a.status in ABSTAIN and not asserted,
        "false_abstention": a.status in ABSTAIN,
        "false_alarm": a.status != "healthy",
        "unsupported_claims": unsupported,
        "overclaim": top is not None and CONF_RANK[top.confidence] > CONF_RANK[exp["max_confidence"]],
        "untraceable_support": not traceable,
        "has_uncertainty": bool(a.uncertainties),
        "keywords_ok": all(k.lower() in text for k in exp["uncertainty_keywords"]),
    }
    return {
        "id": case["id"],
        "split": case["split"],
        "category": case["category"],
        "expected_status": exp["status"],
        "got_status": a.status,
        "ranked": [[c.cause, c.confidence] for c in a.causes],
        "flags": flags,
    }


def _pct(n: int, d: int) -> Optional[float]:
    return None if d == 0 else round(100.0 * n / d, 1)


def summarize(rows: list[dict], cases: dict[str, dict]) -> dict:
    exp = lambda r: cases[r["id"]]["expected"]["status"]  # noqa: E731
    definite = [r for r in rows if exp(r) in DEFINITE]
    abstain = [r for r in rows if exp(r) in ABSTAIN]
    healthy = [r for r in rows if exp(r) == "healthy"]
    assertive = 0
    unsupported = 0
    for r in rows:
        assertive += sum(1 for _, conf in r["ranked"] if CONF_RANK[conf] >= CONF_RANK["moderate"])
        unsupported += len(r["flags"]["unsupported_claims"])
    kw_rows = [r for r in rows if cases[r["id"]]["expected"]["uncertainty_keywords"]]
    return {
        "cases": len(rows),
        "definite_cases": len(definite),
        "abstain_cases": len(abstain),
        "healthy_cases": len(healthy),
        "top1_correct": sum(r["flags"]["top1"] for r in definite),
        "top1_pct": _pct(sum(r["flags"]["top1"] for r in definite), len(definite)),
        "top3_correct": sum(r["flags"]["top3"] for r in definite),
        "top3_pct": _pct(sum(r["flags"]["top3"] for r in definite), len(definite)),
        "assertive_claims": assertive,
        "unsupported_assertive_claims": unsupported,
        "unsupported_claim_pct": _pct(unsupported, assertive),
        "cases_with_unsupported_claim": sum(1 for r in rows if r["flags"]["unsupported_claims"]),
        "overclaim_cases": sum(r["flags"]["overclaim"] for r in rows),
        "untraceable_support_cases": sum(r["flags"]["untraceable_support"] for r in rows),
        "correct_abstentions": sum(r["flags"]["abstained"] for r in abstain),
        "correct_abstention_pct": _pct(sum(r["flags"]["abstained"] for r in abstain), len(abstain)),
        "false_abstentions": sum(r["flags"]["false_abstention"] for r in definite),
        "false_abstention_pct": _pct(sum(r["flags"]["false_abstention"] for r in definite), len(definite)),
        "false_alarms": sum(r["flags"]["false_alarm"] for r in healthy),
        "false_alarm_pct": _pct(sum(r["flags"]["false_alarm"] for r in healthy), len(healthy)),
        "status_exact": sum(r["flags"]["status_match"] for r in rows),
        "status_exact_pct": _pct(sum(r["flags"]["status_match"] for r in rows), len(rows)),
        "uncertainty_present_nonhealthy": sum(r["flags"]["has_uncertainty"] for r in rows if exp(r) != "healthy"),
        "nonhealthy_cases": sum(1 for r in rows if exp(r) != "healthy"),
        "uncertainty_keywords_ok": sum(r["flags"]["keywords_ok"] for r in kw_rows),
        "uncertainty_keyword_cases": len(kw_rows),
    }


def run(dataset_path: pathlib.Path, splits: list[str]) -> dict:
    doc, digest = load_dataset(dataset_path)
    frozen_file = dataset_path.with_suffix(".sha256")
    frozen = frozen_file.read_text().strip() if frozen_file.exists() else None
    cfg = Config()
    selected = [c for c in doc["cases"] if c["split"] in splits]
    cases = {c["id"]: c for c in selected}
    rule_rows, naive_rows = [], []
    for c in selected:
        ev = evidence_from_spec(deep_merge(doc["baseline"], c["evidence"]))
        findings = run_diagnostics(ev, cfg)
        rule_rows.append(evaluate_case(c, analyze(findings, ev, cfg)))
        naive_rows.append(evaluate_case(c, naive_analyze(findings)))
    result = {
        "schema_version": 1,
        "dataset_sha256": digest,
        "dataset_matches_freeze": frozen == digest,
        "splits_evaluated": splits,
        "rule_based": summarize(rule_rows, cases),
        "naive_severity_only": summarize(naive_rows, cases),
        "cases": rule_rows,
    }
    if len(splits) > 1:
        for s in splits:
            sel = [r for r in rule_rows if r["split"] == s]
            result.setdefault("by_split", {})[s] = summarize(sel, cases)
    return result


# ---------------------------------------------------------------- output ----


def _line(label: str, rule: dict, naive: dict, key: str, count: str, total: str) -> str:
    def f(m):
        return f"{m[count]}/{m[total]} ({m[key]}%)" if m[total] else "n/a"

    return f"  {label:<44}{f(rule):<18}{f(naive):<18}"


def print_report(res: dict, verbose: bool) -> None:
    r, n = res["rule_based"], res["naive_severity_only"]
    print(f"dataset sha256: {res['dataset_sha256'][:16]}...  matches freeze record: {res['dataset_matches_freeze']}")
    print(
        f"splits: {', '.join(res['splits_evaluated'])}   cases: {r['cases']} "
        f"(definite {r['definite_cases']}, abstain {r['abstain_cases']}, healthy {r['healthy_cases']})\n"
    )
    print(f"  {'metric':<44}{'rule-based':<18}{'naive severity-only':<18}")
    rows = [
        ("top-1 accuracy (definite cases)", "top1_pct", "top1_correct", "definite_cases"),
        ("top-3 accuracy (definite cases)", "top3_pct", "top3_correct", "definite_cases"),
        ("correct abstention (abstain cases)", "correct_abstention_pct", "correct_abstentions", "abstain_cases"),
        ("false abstention (definite cases)", "false_abstention_pct", "false_abstentions", "definite_cases"),
        ("false alarm (healthy cases)", "false_alarm_pct", "false_alarms", "healthy_cases"),
        ("unsupported assertive claims", "unsupported_claim_pct", "unsupported_assertive_claims", "assertive_claims"),
        ("status exact match (all cases)", "status_exact_pct", "status_exact", "cases"),
    ]
    for label, key, count, total in rows:
        print(_line(label, r, n, key, count, total))
    def two(label, key):
        print(f"  {label:<44}{r[key]:<18}{n[key]:<18}")

    two("overclaim cases (confidence > justified)", "overclaim_cases")
    two("cases with an unsupported claim", "cases_with_unsupported_claim")
    two("cases with untraceable support", "untraceable_support_cases")
    up = f"{r['uncertainty_present_nonhealthy']}/{r['nonhealthy_cases']}"
    print(f"  {'uncertainty present (non-healthy cases)':<44}{up}")
    kw = f"{r['uncertainty_keywords_ok']}/{r['uncertainty_keyword_cases']}"
    print(f"  {'uncertainty keywords covered':<44}{kw}")
    if verbose or any(not (c["flags"]["status_match"] and not c["flags"]["unsupported_claims"]) for c in res["cases"]):
        print("\n  per-case results (only mismatches unless -v):")
        for c in res["cases"]:
            f = c["flags"]
            bad = (not f["status_match"]) or f["unsupported_claims"] or f["overclaim"] or f["untraceable_support"]
            if verbose or bad:
                mark = "FAIL" if bad else " ok "
                ranked = ", ".join(f"{a}:{b}" for a, b in c["ranked"][:3]) or "-"
                print(
                    f"   [{mark}] {c['id']:<26} expected={c['expected_status']:<16} "
                    f"got={c['got_status']:<16} ranked=[{ranked}]"
                    + (f" UNSUPPORTED={f['unsupported_claims']}" if f["unsupported_claims"] else "")
                    + (" OVERCLAIM" if f["overclaim"] else "")
                )


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m syshealth.analysis_eval", description=__doc__.split("\n")[0])
    p.add_argument("--dataset", type=pathlib.Path, default=DEFAULT_DATASET)
    p.add_argument("--split", choices=("dev", "heldout", "all"), default="all")
    p.add_argument("--json", type=pathlib.Path, metavar="FILE", help="write the full results as JSON")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    splits = ["dev", "heldout"] if args.split == "all" else [args.split]
    res = run(args.dataset, splits)
    print_report(res, args.verbose)
    if args.json:
        args.json.write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
