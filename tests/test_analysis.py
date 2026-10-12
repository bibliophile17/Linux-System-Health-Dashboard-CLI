"""Deterministic tests for the rule-based incident analysis and its evaluation harness. Synthetic data only."""

import copy
import hashlib
import json
import pathlib

import pytest

from syshealth import analysis_eval as ae
from syshealth.analysis import CONF_RANK, analyze, render_analysis
from syshealth.cli import main
from syshealth.config import Config
from syshealth.diagnostics import run_diagnostics

DATASET = ae.DEFAULT_DATASET
DOC = json.loads(DATASET.read_text())
CASES = {c["id"]: c for c in DOC["cases"]}


def run_case(case_id, mutate=None):
    spec = ae.deep_merge(DOC["baseline"], CASES[case_id]["evidence"])
    if mutate:
        mutate(spec)
    ev = ae.evidence_from_spec(spec)
    cfg = Config()
    return analyze(run_diagnostics(ev, cfg), ev, cfg), ev


def test_healthy_system_reports_no_cause():
    a, _ = run_case("healthy-01")
    assert a.status == "healthy" and a.causes == []


def test_cpu_saturation_is_top_and_marked_hypothesis():
    a, _ = run_case("cpu-01")
    assert a.causes[0].cause == "cpu_saturation"
    assert all(c.is_hypothesis for c in a.causes)
    assert "not established" in a.disclaimer.lower() or "hypotheses" in a.disclaimer.lower()


def test_oom_service_failure_ranked_after_memory_pressure():
    a, _ = run_case("mem-02")
    causes = [c.cause for c in a.causes]
    assert causes.index("memory_pressure") < causes.index("service_failure")
    svc = next(c for c in a.causes if c.cause == "service_failure")
    assert svc.consequence_of == "memory_pressure"


def test_missing_key_metrics_abstains_instead_of_guessing():
    a, _ = run_case("unav-01")
    assert a.status == "insufficient_data" and a.causes == []
    assert a.uncertainties


def test_unchecked_services_never_asserted_healthy():
    a, _ = run_case("healthy-01", lambda spec: spec.update(commands_run=False, failed_units=None))
    assert a.status != "diagnosed"
    assert any("service" in u.lower() for u in a.uncertainties + a.not_assessed)


def test_every_supporting_statement_is_a_real_observation():
    for cid in CASES:
        a, _ = run_case(cid)
        for c in a.causes:
            for s in c.supporting:
                assert s in a.observations, (cid, s)


def test_single_signal_cannot_reach_strong_with_contradiction():
    def calm_psi(spec):
        spec["pressure"] = {"cpu": [0.0, 0.0], "memory": [0.0, 0.0], "io": [0.0, 0.0]}
        spec["loadavg"] = [0.1, 0.1, 0.1]
    a, _ = run_case("cpu-01", calm_psi)
    if a.causes:
        assert CONF_RANK[a.causes[0].confidence] < CONF_RANK["strong"]


def test_next_steps_are_read_only_commands():
    banned = ("kill", "rm ", "systemctl restart", "systemctl stop", "iptables", "sudo", "reboot", "mkfs", "> /")
    for cid in CASES:
        a, _ = run_case(cid)
        for c in a.causes:
            for step in c.next_steps:
                assert not any(b in step for b in banned), step


def test_analysis_is_deterministic_and_does_not_mutate_evidence():
    spec = ae.deep_merge(DOC["baseline"], CASES["cpu-01"]["evidence"])
    ev = ae.evidence_from_spec(spec)
    cfg = Config()
    findings = run_diagnostics(ev, cfg)
    before = repr(findings)
    first = analyze(findings, ev, cfg).to_dict()
    second = analyze(findings, ev, cfg).to_dict()
    assert first == second and repr(findings) == before


@pytest.mark.parametrize("bad", [None, "x", 5])
def test_malformed_dataset_values_do_not_crash_analysis(bad):
    def corrupt(spec):
        spec["pressure"] = None
        spec["sockets"] = None
        spec["diskio"] = None
        spec["oom_kills"] = None
        spec["failed_units"] = None
    a, _ = run_case("cpu-01", corrupt)
    assert a.status in {"diagnosed", "inconclusive", "insufficient_data", "multiple_issues"}


def test_render_text_includes_disclaimer_and_uncertainty():
    a, _ = run_case("cpu-01")
    text = render_analysis(a)
    assert "Uncertainties" in text and "hypotheses" in text.lower()


# --- dataset and evaluation ---------------------------------------------------

def test_dataset_matches_freeze_record():
    digest = hashlib.sha256(DATASET.read_bytes()).hexdigest()
    assert digest == DATASET.with_suffix(".sha256").read_text().strip()


def test_dataset_schema_and_split():
    assert len({c["id"] for c in DOC["cases"]}) == len(DOC["cases"])
    for c in DOC["cases"]:
        assert c["split"] in {"dev", "heldout"}
        for k in ("injected_condition", "evidence", "uncertainty", "expected"):
            assert k in c, c["id"]
        for k in ("status", "acceptable_primary", "valid_causes", "required_in_top3", "max_confidence",
                  "uncertainty_keywords"):
            assert k in c["expected"], c["id"]
    assert {c["split"] for c in DOC["cases"]} == {"dev", "heldout"}


def test_committed_results_match_a_fresh_run():
    committed = json.loads(pathlib.Path(ae.ROOT, "eval", "results.json").read_text())
    fresh = ae.run(DATASET, ["dev", "heldout"])
    assert json.loads(json.dumps(fresh)) == committed


def test_evaluation_scores_a_deliberately_wrong_answer_as_wrong():
    case = copy.deepcopy(CASES["cpu-01"])
    case["expected"]["acceptable_primary"] = ["memory_pressure"]
    case["expected"]["required_in_top3"] = ["memory_pressure"]
    case["expected"]["valid_causes"] = ["memory_pressure"]
    a, _ = run_case("cpu-01")
    row = ae.evaluate_case(case, a)
    assert not row["flags"]["top1"] and row["flags"]["unsupported_claims"] == ["cpu_saturation"]


# --- CLI ---------------------------------------------------------------------

def test_cli_analyze_json_is_clean_stdout(capsys, tmp_path):
    code = main(["analyze", "--json", "--no-commands", "--sample", "0.1"])
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["analysis"]["method"].startswith("rule-based")
    assert code in (0, 1, 2, 3)
