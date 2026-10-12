import json
import os
import stat

import pytest
from helpers import everything_bad, make_evidence

from syshealth import cli
from syshealth.alerts import AlertEngine
from syshealth.config import Config
from syshealth.diagnostics import run_diagnostics
from syshealth.export import dumps
from syshealth.report import build_incident, write_exclusive


def incident(ev, logs=None, requested=False):
    eng = AlertEngine(Config())
    eng.evaluate(ev.snap)
    return build_incident(ev, run_diagnostics(ev, Config()), eng, Config(), logs, requested)


# ---- report content / reproducibility --------------------------------------
def test_incident_is_byte_for_byte_reproducible():
    assert dumps(incident(everything_bad())) == dumps(incident(everything_bad()))


def test_incident_structure_and_headline():
    r = incident(everything_bad())
    assert r["schema_version"] == 1 and r["incident_id"].startswith("inc-") and len(r["incident_id"]) == 16
    assert r["summary"]["status"] == "critical" and r["summary"]["headline"].startswith("critical - ")
    assert r["summary"]["counts"]["critical"] == 5 and r["summary"]["counts"]["warning"] == 3
    ids = [f["id"] for f in r["findings"]]
    assert ids[:5] == sorted(ids[:5]) and set(ids) == {"cpu", "memory", "disk_space", "disk_io", "process_count",
                                                      "services", "sockets", "network_errors"}   # worst first, then by id
    assert r["alerts"]["active"] and r["snapshot"]["hostname"] == "testhost"
    assert r["generated_at"].endswith("+00:00") and "privacy_note" in r
    json.loads(dumps(r))                                                  # serialisable, strict JSON


def test_healthy_incident_and_not_assessed_listing():
    r = incident(make_evidence(failed=None, commands_run=False))
    assert r["summary"]["status"] == "ok" and r["findings"] == []
    assert r["summary"]["not_assessed"] == ["services"] and r["summary"]["headline"].startswith("No issues")
    assert r["collection"]["commands_run"] is False


def test_logs_only_present_when_requested_and_marked_unavailable_if_unreadable():
    ev = make_evidence()
    assert incident(ev)["logs"] is None
    assert incident(ev, ["line1"], True)["logs"]["lines"] == ["line1"]
    unreadable = incident(ev, None, True)["logs"]
    assert unreadable["available"] is False and unreadable["lines"] == []


def test_report_contains_no_command_lines_or_environment():
    r = incident(everything_bad())
    r.pop("privacy_note")                          # the note itself *mentions* what is excluded
    text = dumps(r)
    for forbidden in ("cmdline", "environ", "HOME=", "SECRET", "password"):
        assert forbidden not in text
    procs = r["snapshot"]["top_cpu"] + r["snapshot"]["top_mem"]
    assert procs and all(set(p) == {"pid", "name", "cpu_percent", "mem_percent"} for p in procs)   # names only


# ---- safe file writing ------------------------------------------------------
def test_write_exclusive_refuses_overwrite_and_sets_private_mode(tmp_path):
    p = tmp_path / "r.json"
    write_exclusive(str(p), '{"a": 1}')
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600 and p.read_text().endswith("\n")
    with pytest.raises(FileExistsError):
        write_exclusive(str(p), "new")
    assert json.loads(p.read_text()) == {"a": 1}                           # original untouched
    write_exclusive(str(p), '{"a": 2}', force=True)
    assert json.loads(p.read_text()) == {"a": 2}


# ---- CLI --------------------------------------------------------------------
@pytest.fixture
def fake_gather(monkeypatch):
    calls = []

    def install(**kw):
        def _g(interval, top_n=5, run_commands=True, **_):
            calls.append({"run_commands": run_commands})
            return make_evidence(commands_run=run_commands, **kw)
        monkeypatch.setattr(cli, "gather", _g)
        return calls
    return install


def run_cli(capsys, *argv):
    code = cli.main(list(argv))
    o = capsys.readouterr()
    return code, o.out, o.err


def test_diagnose_exit_codes(fake_gather, capsys):
    fake_gather()
    assert run_cli(capsys, "diagnose", "--no-color")[0] == 0
    fake_gather(snap_kw=dict(cpu=85.0))
    assert run_cli(capsys, "diagnose", "--no-color")[0] == 1
    fake_gather(snap_kw=dict(cpu=97.0))
    assert run_cli(capsys, "diagnose", "--no-color")[0] == 2
    fake_gather(snap_kw=dict(cpu=None, mem=None, procs=None, load1=None, disks="unreadable"))
    assert run_cli(capsys, "diagnose", "--no-color")[0] == 3


def test_diagnose_text_hides_ok_checks_unless_all(fake_gather, capsys):
    from helpers import proc
    fake_gather(snap_kw=dict(cpu=97.0), top_cpu=[proc(7, "hog", 180.0, 1.0)])
    _, out, _ = run_cli(capsys, "diagnose", "--no-color")
    assert "[CRIT] cpu" in out and "memory" not in out
    assert "Possible explanations (unverified hypotheses)" in out and "Follow-up (read-only, run by you)" in out
    _, out_all, _ = run_cli(capsys, "diagnose", "--no-color", "--all")
    assert "[ OK ] memory" in out_all and "\033[" not in out_all


def test_diagnose_json_is_pure(fake_gather, capsys):
    fake_gather(snap_kw=dict(cpu=97.0))
    code, out, err = run_cli(capsys, "diagnose", "--json")
    doc = json.loads(out)
    assert code == 2 and err == "" and doc["status"] == "critical" and len(doc["findings"]) == 8
    assert {"observations", "hypotheses", "follow_up", "limitations"} <= set(doc["findings"][0])


def test_no_commands_flag_is_honoured(fake_gather, capsys):
    calls = fake_gather()
    run_cli(capsys, "diagnose", "--no-commands")
    run_cli(capsys, "diagnose")
    assert [c["run_commands"] for c in calls] == [False, True]


def test_diagnose_respects_config_errors(fake_gather, capsys):
    fake_gather()
    code, out, err = run_cli(capsys, "diagnose", "--warn", "cpu=99")
    assert code == 2 and "config error" in err and out == ""


def test_incident_to_stdout_is_pure_json(fake_gather, capsys):
    fake_gather(snap_kw=dict(disks={"/": 95}))
    code, out, err = run_cli(capsys, "incident")
    doc = json.loads(out)
    assert code == 2 and err == "" and doc["summary"]["status"] == "critical" and doc["logs"] is None


def test_incident_file_output_no_overwrite_without_force(fake_gather, capsys, tmp_path):
    fake_gather(snap_kw=dict(cpu=85.0))
    path = tmp_path / "inc.json"
    code, out, _ = run_cli(capsys, "incident", "-o", str(path))
    assert code == 1 and "written to" in out and json.loads(path.read_text())["summary"]["status"] == "warning"
    original = path.read_text()
    code, out, err = run_cli(capsys, "incident", "-o", str(path))
    assert code == 2 and "exists" in err and path.read_text() == original      # refused, untouched
    assert run_cli(capsys, "incident", "-o", str(path), "--force")[0] == 1


def test_incident_unwritable_path_is_a_clean_error(fake_gather, capsys, tmp_path):
    fake_gather()
    code, _, err = run_cli(capsys, "incident", "-o", str(tmp_path / "no_dir" / "x.json"))
    assert code == 2 and "cannot write" in err


@pytest.mark.parametrize("n", ["-1", "201"])
def test_incident_include_logs_range_validated(fake_gather, capsys, n):
    fake_gather()
    code, _, err = run_cli(capsys, "incident", "--include-logs", n)
    assert code == 2 and "between 0 and 200" in err


def test_incident_logs_opt_in(fake_gather, capsys, monkeypatch):
    fake_gather()
    monkeypatch.setattr(cli, "read_journal_errors", lambda n: [f"err line (n={n})"])
    doc = json.loads(run_cli(capsys, "incident", "--include-logs", "5")[1])
    assert doc["logs"]["lines"] == ["err line (n=5)"]
    assert json.loads(run_cli(capsys, "incident")[1])["logs"] is None
    doc = json.loads(run_cli(capsys, "incident", "--include-logs", "5", "--no-commands")[1])
    assert doc["logs"]["available"] is False                                    # --no-commands blocks journalctl


def test_show_findings_adds_section_and_never_runs_commands(fake_gather, capsys):
    calls = fake_gather(snap_kw=dict(cpu=97.0))
    code, out, _ = run_cli(capsys, "show", "--findings", "--no-color")
    assert code == 2 and "== Findings" in out and "[CRIT] cpu" in out and calls == [{"run_commands": False}]
    code, out, _ = run_cli(capsys, "show", "--findings", "--json")
    doc = json.loads(out)
    assert len(doc["findings"]) == 8 and doc["status"] == "critical"


def test_plain_show_has_no_findings_key(monkeypatch, capsys):
    from helpers import make_snap
    monkeypatch.setattr(cli, "collect", lambda *a, **k: make_snap())
    assert "findings" not in json.loads(run_cli(capsys, "show", "--json")[1])
