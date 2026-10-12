import pytest
from helpers import T0, make_snap

from syshealth.alerts import AlertEngine, append_log, classify, load_state, save_state
from syshealth.config import Config


def run(engine, **kw):
    return engine.evaluate(make_snap(**kw))


def kinds(events):
    return [(e["event"], e["metric"], e["target"], e["severity"]) for e in events]


def test_classify_boundaries():
    assert classify(79.9, 80, 95) == "ok"
    assert classify(80, 80, 95) == "warning"     # threshold itself triggers
    assert classify(95, 80, 95) == "critical"


def test_healthy_system_produces_nothing():
    e = AlertEngine(Config())
    assert run(e) == [] and e.active == [] and e.worst == "ok"


# ---- transitions / dedupe ---------------------------------------------------
def test_open_once_then_deduplicated_while_condition_persists():
    e = AlertEngine(Config())
    first = run(e, cpu=85.0, ts=T0)
    assert kinds(first) == [("opened", "cpu_percent", "host", "warning")]
    assert first[0]["value"] == 85.0 and first[0]["threshold"] == 80.0 and first[0]["time"].endswith("+00:00")
    for i in range(1, 6):                          # five more refreshes, still bad
        assert run(e, cpu=86.0 + i, ts=T0 + i) == []
    a = e.active[0]
    assert a["value"] == 91.0 and a["since"] == first[0]["time"]   # value tracked, 'since' stable


def test_escalation_then_recovery_keeps_since():
    e = AlertEngine(Config())
    opened = run(e, cpu=85.0, ts=T0)[0]
    esc = run(e, cpu=96.0, ts=T0 + 10)
    assert kinds(esc) == [("escalated", "cpu_percent", "host", "critical")]
    assert esc[0]["previous_severity"] == "warning" and esc[0]["threshold"] == 95.0
    assert e.active[0]["since"] == opened["time"] and e.worst == "critical"
    down = run(e, cpu=50.0, ts=T0 + 20)             # straight back to healthy
    assert kinds(down) == [("resolved", "cpu_percent", "host", "ok")]
    assert down[0]["previous_severity"] == "critical"
    assert e.active == [] and e.worst == "ok"


def test_reopen_after_resolution_is_a_new_alert():
    e = AlertEngine(Config())
    run(e, cpu=90.0, ts=T0)
    run(e, cpu=10.0, ts=T0 + 5)
    ev = run(e, cpu=90.0, ts=T0 + 9)
    assert kinds(ev) == [("opened", "cpu_percent", "host", "warning")]
    assert e.active[0]["since"] == ev[0]["time"]


def test_hysteresis_prevents_flapping_at_warning_boundary():
    e = AlertEngine(Config())                        # warn 80, hysteresis 3% -> clears below 77.6
    assert len(run(e, cpu=81.0)) == 1
    assert run(e, cpu=79.0) == []                    # below warn but inside the hysteresis band
    assert run(e, cpu=77.7) == []
    assert kinds(run(e, cpu=77.5)) == [("resolved", "cpu_percent", "host", "ok")]


def test_hysteresis_on_critical_deescalates_to_warning():
    e = AlertEngine(Config())                        # crit 95 -> relaxed 92.15
    run(e, cpu=96.0)
    assert run(e, cpu=93.0) == []                    # still critical inside band
    ev = run(e, cpu=90.0)
    assert kinds(ev) == [("deescalated", "cpu_percent", "host", "warning")]
    assert e.worst == "warning"


def test_zero_hysteresis_resolves_immediately():
    e = AlertEngine(Config(hysteresis=0.0))
    run(e, cpu=81.0)
    assert kinds(run(e, cpu=79.9)) == [("resolved", "cpu_percent", "host", "ok")]


def test_threshold_never_goes_the_wrong_way_with_hysteresis():
    e = AlertEngine(Config())
    run(e, cpu=81.0)                                 # warning
    # a value that is "critical-ish" only under relaxed thresholds must not escalate
    assert run(e, cpu=93.0) == []                    # 93 < 95: no escalation, no event
    assert e.active[0]["severity"] == "warning"


def test_multiple_targets_tracked_independently():
    e = AlertEngine(Config())
    ev = run(e, disks={"/": 85, "/data": 95, "/boot": 10})
    assert sorted(kinds(ev)) == [("opened", "disk_percent", "/", "warning"),
                                 ("opened", "disk_percent", "/data", "critical")]
    assert [a["target"] for a in e.active] == ["/data", "/"]       # critical sorts first
    ev = run(e, disks={"/": 85, "/data": 20, "/boot": 10})
    assert kinds(ev) == [("resolved", "disk_percent", "/data", "ok")]
    assert [a["target"] for a in e.active] == ["/"]


def test_load_and_process_count_alerts():
    e = AlertEngine(Config())
    ev = run(e, load1=5.0, cores=2, procs=9000)      # load/core = 2.5 (crit), procs crit
    assert sorted(kinds(ev)) == [("opened", "load_per_core", "host", "critical"),
                                 ("opened", "process_count", "host", "critical")]


def test_swap_is_not_evaluated_when_no_swap_configured():
    e = AlertEngine(Config())
    assert run(e, swap=None) == []


# ---- missing data must never look like recovery ----------------------------
def test_unreadable_metric_keeps_existing_alert():
    e = AlertEngine(Config())
    run(e, cpu=96.0)
    assert run(e, cpu=None) == []                    # cpu unreadable this cycle
    assert e.worst == "critical" and e.active[0]["metric"] == "cpu_percent"


def test_unreadable_metric_does_not_open_alert():
    e = AlertEngine(Config())
    assert run(e, cpu=None, mem=None, procs=None, load1=None, disks="unreadable") == []
    assert e.active == []


def test_unreadable_disks_keep_disk_alert_but_vanished_mount_resolves():
    e = AlertEngine(Config())
    run(e, disks={"/data": 95})
    assert run(e, disks="unreadable") == []          # can't see disks: no false recovery
    assert e.worst == "critical"
    ev = run(e, disks={"/": 10})                     # disks readable, /data gone
    assert kinds(ev) == [("resolved", "disk_percent", "/data", "ok")]
    assert ev[0]["reason"] == "target no longer present" and ev[0]["value"] is None


def test_load_alert_kept_when_cpu_count_unknown():
    e = AlertEngine(Config())
    run(e, load1=5.0, cores=2)
    ev = e.evaluate(make_snap(load1=5.0, cores=0))   # cpu_count falsy -> load not computable
    assert ev == [] and any(a["metric"] == "load_per_core" for a in e.active)


# ---- persistence / cross-run dedupe ----------------------------------------
def test_state_roundtrip_dedupes_across_runs(tmp_path):
    path = str(tmp_path / "state.json")
    run1 = AlertEngine(Config())
    assert len(run(run1, cpu=90.0, ts=T0)) == 1
    save_state(path, run1.state)
    run2 = AlertEngine(Config(), load_state(path))   # "next cron invocation"
    assert run(run2, cpu=91.0, ts=T0 + 60) == []     # no duplicate 'opened'
    assert run2.active[0]["since"] == run1.active[0]["since"]
    ev = run(run2, cpu=10.0, ts=T0 + 120)
    assert kinds(ev) == [("resolved", "cpu_percent", "host", "ok")]


@pytest.mark.parametrize("content", ["{corrupt", "", "[1, 2]", "null", '"str"', "\x00\x01\x02"])
def test_corrupt_state_file_starts_clean(tmp_path, content):
    p = tmp_path / "state.json"
    p.write_text(content)
    assert load_state(str(p)) == {}


def test_missing_state_file_starts_clean(tmp_path):
    assert load_state(str(tmp_path / "nope.json")) == {}


def test_malformed_entries_in_state_are_dropped():
    state = {"ok|1": {"metric": "cpu_percent", "target": "host", "severity": "critical", "since": "t"},
             "bad1": "string", "bad2": {"severity": "ok"}, "bad3": {"metric": "x", "target": "y", "severity": "weird", "since": "t"},
             "bad4": {"metric": 5, "target": "y", "severity": "warning", "since": "t"}}
    e = AlertEngine(Config(), state)
    assert list(e.state) == ["ok|1"]


def test_save_state_is_atomic_and_leaves_no_temp_files(tmp_path):
    p = tmp_path / "state.json"
    save_state(str(p), {"k": {"metric": "m"}})
    save_state(str(p), {"k2": {"metric": "m"}})
    assert load_state(str(p)) == {"k2": {"metric": "m"}}
    assert [f.name for f in tmp_path.iterdir()] == ["state.json"]


def test_alert_log_is_json_lines(tmp_path):
    import json
    p = tmp_path / "a.jsonl"
    e = AlertEngine(Config())
    append_log(str(p), run(e, cpu=90.0))
    append_log(str(p), run(e, cpu=91.0))            # deduped: nothing appended
    append_log(str(p), [])
    lines = p.read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["event"] == "opened"
