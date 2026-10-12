import copy
import re

from helpers import everything_bad, make_evidence, proc

from syshealth import diagnostics as d
from syshealth.config import Config, parse_config
from syshealth.evidence import DiskIORate, Listener, Pressure, SocketSummary

CFG = Config()
HEDGE = re.compile(r"\b(may|might|possible|possibly|appears?|can|could|usually|common|cannot)\b", re.I)
ALLOWED_FIRST = {"top", "vmstat", "pidstat", "cat", "ps", "free", "df", "du", "ss", "ip", "iostat", "journalctl",
                 "systemctl", "dmesg", "ethtool", "nstat", "lsof"}
FORBIDDEN = re.compile(r"\b(kill|pkill|killall|rm|restart|stop|start|reboot|shutdown|iptables|nft|chmod|chown|mv|"
                       r"renice|tee|mount|umount|systemctl\s+(enable|disable|mask)|sysctl\s+-w|dd|mkfs)\b|-delete|>\s*/(?!dev/null)")


def by_id(findings):
    return {f.id: f for f in findings}


def run(ev, cfg=CFG):
    return by_id(d.run_diagnostics(ev, cfg))


# ---- healthy baseline -------------------------------------------------------
def test_healthy_system_has_no_problem_findings():
    f = run(make_evidence())
    assert {k: v.status for k, v in f.items()} == {
        "cpu": "ok", "memory": "ok", "disk_space": "ok", "disk_io": "ok", "process_count": "ok",
        "services": "ok", "sockets": "ok", "network_errors": "ok"}
    assert all(not v.hypotheses and not v.follow_up for v in f.values())      # nothing speculative when healthy
    assert d.highest(list(f.values())) == "ok"


# ---- CPU --------------------------------------------------------------------
def test_cpu_dominant_process_hypothesis_is_hedged_not_asserted():
    ev = make_evidence(snap_kw=dict(cpu=90.0, cores=2), top_cpu=[proc(7, "hog", 170.0, 1.0), proc(8, "x", 5.0, 1.0)])
    f = run(ev)["cpu"]
    assert f.status == "warning"
    assert any("90.0%" in o for o in f.observations) and any("hog (pid 7) 170.0%" in o for o in f.observations)
    assert any("hog" in h and "not been confirmed" in h for h in f.hypotheses)


def test_cpu_spread_across_many_processes():
    ev = make_evidence(snap_kw=dict(cpu=90.0, cores=2), top_cpu=[proc(7, "a", 30.0, 1.0)])
    assert any("spread across many" in h for h in run(ev)["cpu"].hypotheses)


def test_high_load_with_low_cpu_suggests_blocked_tasks():
    f = run(make_evidence(snap_kw=dict(cpu=10.0, load1=6.0, cores=2)))["cpu"]
    assert f.status == "critical" and any("blocked on I/O" in h for h in f.hypotheses)


def test_cpu_pressure_alone_triggers():
    f = run(make_evidence(pressure={"cpu": Pressure(12.0, None)}))["cpu"]
    assert f.status == "warning" and any("pressure" in o for o in f.observations)


def test_cpu_unknown_when_unreadable():
    f = run(make_evidence(snap_kw=dict(cpu=None, load1=None)))["cpu"]
    assert f.status == "unknown" and "Could not assess" in f.summary


def test_custom_thresholds_change_outcome():
    ev = make_evidence(snap_kw=dict(cpu=60.0))
    assert run(ev)["cpu"].status == "ok"
    cfg = parse_config({"thresholds": {"cpu_percent": {"warn": 50, "crit": 58}}})
    assert run(ev, cfg)["cpu"].status == "critical"


# ---- memory -----------------------------------------------------------------
def test_memory_critical_with_dominant_process_and_swap():
    ev = make_evidence(snap_kw=dict(mem=97.0, swap=90.0), oom=2, top_mem=[proc(5, "bigmem", 1.0, 60.0)])
    f = run(ev)["memory"]
    assert f.status == "critical"
    assert any("97.0%" in o for o in f.observations) and any("OOM-killer invocations since boot: 2" in o for o in f.observations)
    assert any("leak or an intended working set cannot be determined" in h for h in f.hypotheses)
    assert any("swap" in h for h in f.hypotheses) and any("OOM killer" in h for h in f.hypotheses)


def test_oom_history_alone_is_info_not_alarm():
    f = run(make_evidence(oom=4))["memory"]
    assert f.status == "info" and "since boot" in f.summary


def test_memory_unknown_and_no_swap_wording():
    assert run(make_evidence(snap_kw=dict(mem=None)))["memory"].status == "unknown"
    ev = make_evidence(snap_kw=dict(mem=90.0))                        # warning path lists the no-swap fact
    assert any("no swap configured" in o for o in d.diag_memory(ev, CFG).observations)


# ---- disk space -------------------------------------------------------------
def test_disk_space_flags_only_full_mounts_and_quotes_paths():
    ev = make_evidence(snap_kw=dict(disks={"/": 30, "/my data": 92, "/var": 85}))
    f = run(ev)["disk_space"]
    assert f.status == "critical" and len(f.observations) == 2
    assert f.observations[0].startswith("/my data") and "92.0% used" in f.observations[0]    # worst first
    assert any("'/my data'" in c for c in f.follow_up)                                         # shell-quoted
    assert all("/ (" not in o for o in f.observations)                                         # healthy mount omitted


def test_disk_space_warning_only_and_unreadable():
    assert run(make_evidence(snap_kw=dict(disks={"/": 85})))["disk_space"].status == "warning"
    assert run(make_evidence(snap_kw=dict(disks="unreadable")))["disk_space"].status == "unknown"


# ---- disk I/O ---------------------------------------------------------------
def test_disk_io_saturation_and_hedging():
    ev = make_evidence(diskio=[DiskIORate("sda", 95.0, 1e7, 2e7, 5000.0, 42.0), DiskIORate("sdb", 10.0, 0, 0, 0.0, None)])
    f = run(ev)["disk_io"]
    assert f.status == "critical" and f.observations[0].startswith("sda: 95% busy") and "avg wait 42.0 ms" in f.observations[0]
    assert any("may be saturated" in h for h in f.hypotheses)
    assert any("NVMe" in text for text in f.limitations)


def test_disk_io_pressure_without_busy_device_and_unknown():
    assert run(make_evidence(pressure={"io": Pressure(15.0, 5.0)}))["disk_io"].status == "warning"
    assert run(make_evidence(diskio=None))["disk_io"].status == "unknown"


# ---- process count ----------------------------------------------------------
def test_process_count_levels():
    assert run(make_evidence(snap_kw=dict(procs=2500)))["process_count"].status == "warning"
    f = run(make_evidence(snap_kw=dict(procs=9000)))["process_count"]
    assert f.status == "critical" and "9000 processes" in f.observations[0]
    assert any("cannot tell these apart" in h for h in f.hypotheses)
    assert run(make_evidence(snap_kw=dict(procs=None)))["process_count"].status == "unknown"


# ---- services ---------------------------------------------------------------
def test_failed_units_listed_and_quoted_in_followups():
    f = run(make_evidence(failed=["nginx.service", "weird name.service"]))["services"]
    assert f.status == "warning" and "failed systemd units: 2" in f.observations[0]
    assert any("systemctl status nginx.service" in c for c in f.follow_up)
    assert any("exit reason is not captured" in h for h in f.hypotheses)


def test_failed_unit_list_is_truncated():
    f = run(make_evidence(failed=[f"u{i}.service" for i in range(25)]))["services"]
    assert len(f.observations) <= 13 and any("and 15 more" in o for o in f.observations)


def test_services_unknown_not_ok_when_not_checked():
    assert run(make_evidence(commands_run=False, failed=None))["services"].status == "unknown"
    f = run(make_evidence(failed=None))["services"]                       # systemctl missing/denied
    assert f.status == "unknown" and "unavailable or denied" in f.summary


def test_oom_kills_with_no_failed_units_is_info():
    assert run(make_evidence(oom=3))["services"].status == "info"


# ---- sockets ----------------------------------------------------------------
def test_socket_state_hypotheses():
    sk = SocketSummary([Listener("0.0.0.0", 80)], {"CLOSE_WAIT": 150, "TIME_WAIT": 6000, "SYN_RECV": 120})
    f = run(make_evidence(sockets=sk))["sockets"]
    assert f.status == "warning" and len(f.hypotheses) == 3
    assert any("0.0.0.0:80" in o for o in f.observations) and any("CLOSE_WAIT=150" in o for o in f.observations)


def test_wildcard_listeners_are_observed_but_not_alarming():
    sk = SocketSummary([Listener("0.0.0.0", 22), Listener("127.0.0.1", 5432)], {"LISTEN": 2})
    f = run(make_evidence(sockets=sk))["sockets"]
    assert f.status == "ok" and "1 bound to all interfaces" in f.observations[0]
    assert run(make_evidence(sockets=None))["sockets"].status == "unknown"


# ---- network errors ---------------------------------------------------------
def test_interface_errors_active_vs_historic():
    from syshealth.collectors import NetIface
    active = run(make_evidence(net=[NetIface("eth0", 0, 0, 5, 9, 0, 0, 0, 0)], net_deltas={"eth0": {"errors": 5, "drops": 9}}))
    f = active["network_errors"]
    assert f.status == "warning" and "+5 errors, +9 drops" in f.observations[0] and "since boot: 5 errors, 9 drops" in f.observations[0]
    historic = run(make_evidence(net=[NetIface("eth0", 0, 0, 5, 9, 0, 0, 0, 0)], net_deltas={"eth0": {"errors": 0, "drops": 0}}))
    assert historic["network_errors"].status == "info" and "unchanged in this window" in historic["network_errors"].observations[0]
    assert run(make_evidence(net="unreadable", net_deltas=None))["network_errors"].status == "unknown"


# ---- cross-cutting guarantees ----------------------------------------------
def test_everything_bad_triggers_every_rule():
    f = run(everything_bad())
    assert {k: v.status for k, v in f.items()} == {
        "cpu": "critical", "memory": "critical", "disk_space": "critical", "disk_io": "critical",
        "process_count": "critical", "services": "warning", "sockets": "warning", "network_errors": "warning"}
    assert d.highest(list(f.values())) == "critical"


def test_observations_hypotheses_follow_up_are_kept_separate():
    for f in run(everything_bad()).values():
        assert f.observations and f.hypotheses and f.follow_up and f.limitations and f.why_it_matters, f.id
        for h in f.hypotheses:                                    # every hypothesis is hedged, never asserted
            assert HEDGE.search(h), (f.id, h)
        for o in f.observations:                                  # observations contain no speculation words
            assert not re.search(r"\b(probably|likely|possibly|might)\b", o, re.I), (f.id, o)
        assert not set(f.hypotheses) & set(f.observations)


def test_followup_commands_are_read_only():
    cmds = [c for f in run(everything_bad()).values() for c in f.follow_up]
    assert len(cmds) >= 25
    for c in cmds:
        base = c.split("#")[0]                                    # ignore trailing comments
        assert base.split()[0] in ALLOWED_FIRST, c
        assert not FORBIDDEN.search(base), c
    assert not [c for c in cmds if "sudo" in c]


def test_rules_do_not_mutate_evidence():
    ev = everything_bad()
    before = copy.deepcopy(ev)
    d.run_diagnostics(ev, CFG)
    assert ev == before


def test_a_crashing_rule_becomes_unknown_and_others_still_run(monkeypatch):
    def broken(ev, cfg):
        raise RuntimeError("boom")
    monkeypatch.setattr(d, "RULES", [broken, d.diag_cpu])
    f = d.run_diagnostics(make_evidence(), CFG)
    assert [x.status for x in f] == ["unknown", "ok"] and "RuntimeError" in f[0].summary


def test_highest_ignores_unknown_and_handles_empty():
    from syshealth.diagnostics import Finding
    assert d.highest([]) == "ok"
    assert d.highest([Finding("a", "t", "unknown", "s"), Finding("b", "t", "info", "s")]) == "info"
