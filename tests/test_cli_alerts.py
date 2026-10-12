import json

import pytest
from helpers import make_snap

from syshealth import cli
from syshealth.render import render


@pytest.fixture
def use_snap(monkeypatch):
    def _use(**kw):
        monkeypatch.setattr(cli, "collect", lambda *a, **k: make_snap(**kw))
    return _use


def run_cli(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


# ---- exit codes -------------------------------------------------------------
def test_exit_0_when_healthy(use_snap, capsys):
    use_snap()
    code, out, err = run_cli(capsys, "check", "--no-color")
    assert code == 0 and "none active" in out and err == ""


def test_exit_1_on_warning(use_snap, capsys):
    use_snap(cpu=85.0)
    code, out, _ = run_cli(capsys, "check", "--no-color")
    assert code == 1 and "WARN" in out and "cpu_percent" in out


def test_exit_2_on_critical(use_snap, capsys):
    use_snap(cpu=85.0, mem=97.0)
    code, out, _ = run_cli(capsys, "check", "--no-color")
    assert code == 2 and "CRIT" in out


def test_show_uses_same_exit_codes(use_snap, capsys):
    use_snap(disks={"/": 95})
    code, out, _ = run_cli(capsys, "show", "--no-color")
    assert code == 2 and "== Alerts" in out and "== CPU" in out


def test_exit_3_when_monitoring_itself_fails(use_snap, capsys):
    use_snap(cpu=None, mem=None, procs=None, load1=None, disks="unreadable")
    code, out, _ = run_cli(capsys, "check", "--no-color")
    assert code == 3


def test_exit_2_on_bad_config_with_message_on_stderr(use_snap, capsys, tmp_path):
    use_snap()
    bad = tmp_path / "bad.toml"
    bad.write_text("[thresholds.cpu_percent]\nwarn = 90\ncrit = 10\n")
    code, out, err = run_cli(capsys, "check", "--config", str(bad))
    assert code == 2 and out == "" and "config error" in err and "must be lower" in err


def test_exit_2_on_missing_config_file(use_snap, capsys, tmp_path):
    use_snap()
    code, out, err = run_cli(capsys, "check", "--config", str(tmp_path / "nope.toml"))
    assert code == 2 and "cannot read config" in err and out == ""


def test_exit_2_on_bad_override(use_snap, capsys):
    use_snap()
    code, _, err = run_cli(capsys, "check", "--warn", "bogus=1")
    assert code == 2 and "unknown metric" in err


def test_cli_overrides_change_outcome(use_snap, capsys):
    use_snap(cpu=50.0)
    assert run_cli(capsys, "check", "--no-color")[0] == 0
    assert run_cli(capsys, "check", "--no-color", "--warn", "cpu=40")[0] == 1
    assert run_cli(capsys, "check", "--no-color", "--warn", "cpu=40", "--crit", "cpu=45")[0] == 2


def test_config_file_thresholds_are_used(use_snap, capsys, tmp_path):
    use_snap(cpu=50.0)
    cfg = tmp_path / "c.toml"
    cfg.write_text("[thresholds.cpu_percent]\nwarn = 40\ncrit = 90\n")
    assert run_cli(capsys, "check", "--config", str(cfg))[0] == 1


def test_argparse_usage_errors_exit_2(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["check", "--sample", "0"])
    assert e.value.code == 2


# ---- JSON -------------------------------------------------------------------
def test_json_output_is_pure_json_on_stdout(use_snap, capsys):
    use_snap(cpu=97.0)
    code, out, err = run_cli(capsys, "check", "--json")
    doc = json.loads(out)                           # whole stdout must parse: no banners, no extra text
    assert code == 2 and err == ""
    assert doc["schema_version"] == 1 and doc["status"] == "critical"
    assert doc["alerts"]["active"][0]["metric"] == "cpu_percent"
    assert doc["alerts"]["events"][0]["event"] == "opened"
    assert doc["thresholds"]["cpu_percent"] == {"warn": 80.0, "crit": 95.0}
    assert doc["snapshot"]["hostname"] == "testhost" and doc["snapshot"]["timestamp_iso"].endswith("+00:00")
    assert out.endswith("}\n") and out.count("\n") > 1   # pretty-printed, single document


def test_json_for_show_and_healthy_system(use_snap, capsys):
    use_snap()
    code, out, _ = run_cli(capsys, "show", "--json")
    doc = json.loads(out)
    assert code == 0 and doc["status"] == "ok" and doc["alerts"] == {"active": [], "events": []}
    assert "== " not in out                          # no human table mixed in


def test_json_missing_metrics_are_null_not_zero(use_snap, capsys):
    use_snap(cpu=None, mem=None, procs=None, load1=None, disks="unreadable")
    code, out, _ = run_cli(capsys, "check", "--json")
    snap = json.loads(out)["snapshot"]
    assert code == 3 and snap["cpu_percent"] is None and snap["memory"] is None
    assert snap["disks"] is None and snap["process_count"] is None


def test_json_is_strict_json_without_nan(use_snap, capsys):
    use_snap(cpu=50.0)
    _, out, _ = run_cli(capsys, "check", "--json")
    json.loads(out, parse_constant=lambda c: pytest.fail(f"non-standard JSON constant {c}"))


def test_json_stays_clean_when_alert_log_unwritable(use_snap, capsys, tmp_path):
    use_snap(cpu=97.0)
    code, out, err = run_cli(capsys, "check", "--json", "--alert-log", str(tmp_path / "no_dir" / "a.jsonl"))
    assert code == 2 and json.loads(out)["status"] == "critical"      # monitoring unaffected
    assert "could not write" in err                                   # reported on stderr only


def test_watch_json_emits_one_object_per_line(monkeypatch, capsys):
    snaps = iter([make_snap(cpu=97.0), make_snap(cpu=97.0), make_snap(cpu=10.0)])
    monkeypatch.setattr(cli, "collect", lambda *a, **k: next(snaps))
    calls = {"n": 0}

    def fake_sleep(_):
        calls["n"] += 1
        if calls["n"] >= 3:
            raise KeyboardInterrupt
    monkeypatch.setattr(cli.time, "sleep", fake_sleep)
    code, out, err = run_cli(capsys, "watch", "--json", "-i", "1")
    docs = [json.loads(line) for line in out.splitlines()]
    assert code == 130 and len(docs) == 3
    assert [d["status"] for d in docs] == ["critical", "critical", "ok"]
    # dedupe inside one watch session: 'opened' appears once, then 'resolved'
    assert [e["event"] for e in docs[-1]["alerts"]["events"]] == ["opened", "resolved"]


# ---- state files through the CLI -------------------------------------------
def test_cross_run_dedupe_with_state_file_and_log(use_snap, capsys, tmp_path):
    use_snap(cpu=97.0)
    state, log = tmp_path / "s.json", tmp_path / "a.jsonl"
    args = ["check", "--json", "--state-file", str(state), "--alert-log", str(log)]
    _, out1, _ = run_cli(capsys, *args)
    _, out2, _ = run_cli(capsys, *args)
    assert len(json.loads(out1)["alerts"]["events"]) == 1      # first run: opened
    d2 = json.loads(out2)
    assert d2["alerts"]["events"] == [] and d2["status"] == "critical"   # second run: still active, no new event
    assert len(log.read_text().splitlines()) == 1               # logged exactly once
    use_snap(cpu=5.0)
    _, out3, _ = run_cli(capsys, *args)
    assert [e["event"] for e in json.loads(out3)["alerts"]["events"]] == ["resolved"]
    assert len(log.read_text().splitlines()) == 2


@pytest.mark.parametrize("content", ["{corrupt", "", "[]", "\x00"])
def test_corrupt_state_file_does_not_crash_cli(use_snap, capsys, tmp_path, content):
    use_snap(cpu=97.0)
    state = tmp_path / "s.json"
    state.write_text(content)
    code, out, err = run_cli(capsys, "check", "--json", "--state-file", str(state))
    assert code == 2 and json.loads(out)["alerts"]["events"][0]["event"] == "opened" and err == ""
    assert json.loads(state.read_text())                       # state file healed with valid JSON


def test_missing_state_file_is_created(use_snap, capsys, tmp_path):
    use_snap(cpu=97.0)
    state = tmp_path / "s.json"
    assert run_cli(capsys, "check", "--state-file", str(state))[0] == 2 and state.exists()


def test_unwritable_state_path_warns_but_still_reports(use_snap, capsys, tmp_path):
    use_snap(cpu=97.0)
    code, out, err = run_cli(capsys, "check", "--no-color", "--state-file", str(tmp_path / "no_dir" / "s.json"))
    assert code == 2 and "CRIT" in out and "could not write" in err


# ---- rendering of alerts ----------------------------------------------------
def test_render_alert_section_text():
    from syshealth.alerts import AlertEngine
    from syshealth.config import Config
    snap = make_snap(cpu=97.0)
    eng = AlertEngine(Config())
    events = eng.evaluate(snap)
    text = render(snap, ["cpu"], False, "cpu", Config().thresholds, eng.active, events)
    assert "CRIT  cpu_percent [host]  97.0 (threshold 95)" in text and "opened" in text
    assert "\033[" not in text
