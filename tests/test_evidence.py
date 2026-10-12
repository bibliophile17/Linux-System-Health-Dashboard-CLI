import subprocess
from types import SimpleNamespace

import pytest
from helpers import make_snap

from syshealth import evidence as ev
from syshealth.collectors import NetIface


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


# ---- /proc/diskstats --------------------------------------------------------
#            maj min name  rc rm sr  msr  wc wm sw  msw if  io_ms wms
def dline(name, rc=0, sr=0, msr=0, wc=0, sw=0, msw=0, io_ms=0):
    return f"   8 0 {name} {rc} 0 {sr} {msr} {wc} 0 {sw} {msw} 0 {io_ms} 0 0 0 0 0 0 0\n"


def test_diskstats_filters_loop_ram_and_partitions(tmp_path):
    write(tmp_path, "proc/diskstats", dline("sda") + dline("sda1") + dline("loop0") + dline("ram0") + dline("zram0"))
    (tmp_path / "sys/block/sda").mkdir(parents=True)
    assert list(ev.read_diskstats(str(tmp_path / "proc"), str(tmp_path / "sys"))) == ["sda"]


def test_diskstats_keeps_everything_when_sys_block_absent(tmp_path):
    write(tmp_path, "proc/diskstats", dline("sda") + dline("sda1"))
    assert set(ev.read_diskstats(str(tmp_path / "proc"), str(tmp_path / "nosys"))) == {"sda", "sda1"}


def test_diskstats_missing_and_malformed(tmp_path):
    assert ev.read_diskstats(str(tmp_path), str(tmp_path)) is None
    write(tmp_path, "diskstats", "short line\n8 0 sda a b c d e f g h i j\n")
    assert ev.read_diskstats(str(tmp_path), str(tmp_path / "nosys")) == {}


def test_disk_io_rate_math():
    prev = {"sda": ev.DiskStat(100, 100, 1000, 1000, 50, 50, 0)}
    curr = {"sda": ev.DiskStat(300, 200, 5096, 3048, 250, 150, 5000)}
    (r,) = ev.disk_io_rates(prev, curr, elapsed=10.0)
    assert r.util_percent == pytest.approx(50.0)                    # 5000 ms busy of 10 000 ms
    assert r.read_bytes_per_s == pytest.approx(4096 * 512 / 10)
    assert r.write_bytes_per_s == pytest.approx(2048 * 512 / 10)
    assert r.iops == pytest.approx(30.0)                            # 300 I/Os in 10 s
    assert r.await_ms == pytest.approx(300 / 300)                   # 300 ms over 300 I/Os


def test_disk_io_idle_device_has_no_await_and_util_is_capped():
    prev = {"a": ev.DiskStat(1, 1, 1, 1, 1, 1, 0), "b": ev.DiskStat(0, 0, 0, 0, 0, 0, 0)}
    curr = {"a": ev.DiskStat(1, 1, 1, 1, 1, 1, 0), "b": ev.DiskStat(1, 0, 0, 0, 1, 0, 99_999)}
    ra, rb = ev.disk_io_rates(prev, curr, 1.0)
    assert ra.await_ms is None and ra.util_percent == 0.0
    assert rb.util_percent == 100.0


def test_disk_io_counter_reset_skipped_and_unreadable_none():
    prev = {"sda": ev.DiskStat(500, 0, 0, 0, 0, 0, 0)}
    curr = {"sda": ev.DiskStat(10, 0, 0, 0, 0, 0, 0), "new": ev.DiskStat(1, 1, 1, 1, 1, 1, 1)}
    assert ev.disk_io_rates(prev, curr, 1.0) == []                   # reset device and unseen device skipped
    assert ev.disk_io_rates(None, curr, 1.0) is None and ev.disk_io_rates(prev, curr, 0.0) is None


# ---- sockets ----------------------------------------------------------------
TCP_HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def tcp_line(local, state, remote="00000000:0000"):
    return f"   0: {local} {remote} {state} 00000000:00000000 00:00000000 00000000     0        0 1 1 0\n"


def test_socket_parsing_ipv4_ipv6_and_states(tmp_path):
    write(tmp_path, "net/tcp", TCP_HEAD + tcp_line("0100007F:1F90", "0A") + tcp_line("00000000:0016", "0A")
          + tcp_line("0100007F:D431", "01", "0100007F:1F90") + tcp_line("0100007F:D432", "06") + tcp_line("0100007F:D433", "08"))
    write(tmp_path, "net/tcp6", TCP_HEAD + tcp_line("00000000000000000000000000000000:0050", "0A")
          + tcp_line("00000000000000000000000001000000:1F91", "0A"))
    sk = ev.read_sockets(str(tmp_path))
    got = {(x.address, x.port) for x in sk.listeners}
    assert got == {("127.0.0.1", 8080), ("0.0.0.0", 22), ("::", 80), ("::1", 8081)}
    assert [x.wildcard for x in sk.listeners if x.port in (22, 80)] == [True, True]
    assert not [x for x in sk.listeners if x.port in (8080, 8081) and x.wildcard]
    assert sk.states == {"LISTEN": 4, "ESTABLISHED": 1, "TIME_WAIT": 1, "CLOSE_WAIT": 1}


def test_socket_malformed_lines_ignored_and_missing_tables(tmp_path):
    assert ev.read_sockets(str(tmp_path)) is None
    write(tmp_path, "net/tcp", TCP_HEAD + "garbage\n" + tcp_line("ZZZZ:1", "0A") + tcp_line("0100007F:1F90", "FF")
          + tcp_line("0100007F:50", "0A"))
    sk = ev.read_sockets(str(tmp_path))
    assert [(x.address, x.port) for x in sk.listeners] == [("127.0.0.1", 80)]


def test_sockets_with_only_ipv4_table_still_work(tmp_path):
    write(tmp_path, "net/tcp", TCP_HEAD + tcp_line("0100007F:50", "0A"))
    assert ev.read_sockets(str(tmp_path)).states == {"LISTEN": 1}


# ---- pressure / OOM ---------------------------------------------------------
def test_pressure_parsing(tmp_path):
    write(tmp_path, "pressure/cpu", "some avg10=1.50 avg60=0.00 avg300=0.00 total=5\n")
    write(tmp_path, "pressure/memory", "some avg10=2.00 avg60=0 avg300=0 total=1\nfull avg10=0.75 avg60=0 avg300=0 total=1\n")
    write(tmp_path, "pressure/io", "garbage\n")
    p = ev.read_pressure(str(tmp_path))
    assert p["cpu"] == ev.Pressure(1.5, None) and p["memory"] == ev.Pressure(2.0, 0.75) and "io" not in p


def test_pressure_unsupported_kernel(tmp_path):
    assert ev.read_pressure(str(tmp_path)) is None


def test_oom_kill_counter(tmp_path):
    assert ev.read_oom_kills(str(tmp_path)) is None
    write(tmp_path, "vmstat", "nr_free_pages 5\n")
    assert ev.read_oom_kills(str(tmp_path)) is None                  # older kernel: counter absent
    write(tmp_path, "vmstat", "nr_free_pages 5\noom_kill 7\n")
    assert ev.read_oom_kills(str(tmp_path)) == 7
    write(tmp_path, "vmstat", "oom_kill many\n")
    assert ev.read_oom_kills(str(tmp_path)) is None


# ---- interface deltas -------------------------------------------------------
def nic(name, re=0, te=0, rd=0, td=0):
    return NetIface(name, 0, 0, re, rd, 0, 0, te, td)


def test_net_deltas_and_counter_reset():
    d = ev.net_deltas([nic("eth0", 1, 1, 2, 2), nic("eth1", 50)], [nic("eth0", 3, 2, 6, 3), nic("eth1", 5), nic("new", 9)])
    assert d == {"eth0": {"errors": 3, "drops": 5}}                   # eth1 reset omitted, 'new' unseen
    assert ev.net_deltas(None, [nic("a")]) is None and ev.net_deltas([nic("a")], None) is None


# ---- external commands: allowlist and failure modes -------------------------
def test_only_allowlisted_commands_can_run(monkeypatch):
    called = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: called.append(a))
    for bad in (["rm", "-rf", "/"], ["systemctl", "restart", "nginx"], ["journalctl", "-p", "err", "-n", "5; reboot"],
                ["systemctl", "--failed"], ["sh", "-c", "id"], []):
        with pytest.raises(ValueError):
            ev._run_allowlisted(bad)
    assert called == []                                                # nothing was ever executed


def test_command_runs_without_shell_with_clean_env_and_timeout(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen.update(argv=argv, **kw)
        return SimpleNamespace(returncode=0, stdout="● nginx.service loaded failed failed Web\nfoo.timer loaded failed failed\n")
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert ev.read_failed_units() == ["nginx.service", "foo.timer"]
    assert seen["shell"] is False and seen["timeout"] and seen["stdin"] == subprocess.DEVNULL
    assert set(seen["env"]) == {"PATH", "LC_ALL"}                      # no inherited environment/secrets


@pytest.mark.parametrize("exc", [FileNotFoundError(), PermissionError(), subprocess.TimeoutExpired("x", 1)])
def test_command_failures_return_none(monkeypatch, exc):
    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(subprocess, "run", boom)
    assert ev.read_failed_units() is None and ev.read_journal_errors(5) is None


def test_nonzero_exit_returns_none(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout="x"))
    assert ev.read_failed_units() is None


def test_journal_lines_are_redacted_and_count_clamped(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return SimpleNamespace(returncode=0, stdout="2026-01-01T00:00:00 app: login password=hunter2 failed\n\n"
                                                    + "x" * 500 + "\n")
    monkeypatch.setattr(subprocess, "run", fake_run)
    lines = ev.read_journal_errors(10_000)
    assert seen["argv"][4] == "200"                                    # clamped
    assert "hunter2" not in lines[0] and "[REDACTED]" in lines[0] and len(lines[1]) == 300


@pytest.mark.parametrize("raw,secret", [
    ("password=hunter2", "hunter2"), ("passwd: abc", "abc"), ("token=XYZ123", "XYZ123"),
    ("api_key=AKIA999", "AKIA999"), ("API-KEY: k3y", "k3y"), ("Authorization: Bearer abc123def456", "abc123def456"),
    ("got Bearer eyJhbGciOi12345 here", "eyJhbGciOi12345"), ("secret abc", "abc")])
def test_redaction(raw, secret):
    assert secret not in ev.redact(raw)


def test_redaction_leaves_ordinary_text():
    assert ev.redact("disk /dev/sda1 is full") == "disk /dev/sda1 is full"


def test_failed_unit_parsing_edge_cases():
    assert ev.parse_failed_units("") == [] and ev.parse_failed_units("\n  \n") == []
    assert ev.parse_failed_units("* a.service x\n● b.service y") == ["a.service", "b.service"]


# ---- gather -----------------------------------------------------------------
def test_gather_on_fake_proc_and_command_switch(tmp_path, monkeypatch):
    write(tmp_path, "proc/diskstats", dline("sda", io_ms=0))
    write(tmp_path, "proc/net/dev", "h1\nh2\n  eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
    write(tmp_path, "proc/vmstat", "oom_kill 2\n")
    (tmp_path / "sys/block/sda").mkdir(parents=True)
    snap = make_snap()
    snap.interval = 2.0

    def fake_collect(interval, top_n, proc):                           # the "system" advances during the window
        write(tmp_path, "proc/diskstats", dline("sda", rc=10, io_ms=1000))
        write(tmp_path, "proc/net/dev", "h1\nh2\n  eth0: 0 0 4 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
        snap.network = ev.read_network(proc)
        return snap
    calls = []
    monkeypatch.setattr(ev, "read_failed_units", lambda: calls.append(1) or ["x.service"])
    kw = dict(proc=str(tmp_path / "proc"), sysroot=str(tmp_path / "sys"), collect_fn=fake_collect)
    e = ev.gather(2.0, **kw)
    assert e.diskio[0].util_percent == pytest.approx(50.0) and e.oom_kills == 2
    assert e.net_deltas == {"eth0": {"errors": 4, "drops": 0}}
    assert e.failed_units == ["x.service"] and e.commands_run is True
    e2 = ev.gather(2.0, run_commands=False, **kw)
    assert e2.failed_units is None and e2.commands_run is False and len(calls) == 1   # no command when disabled
