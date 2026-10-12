import os
from types import SimpleNamespace

import pytest

from syshealth import collectors as c


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


STAT_A = "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 50 0 50 350 50 0 0 0 0 0\ncpu1 50 0 50 350 50 0 0 0 0 0\nintr 1\n"
STAT_B = "cpu  200 0 200 750 150 0 0 0 0 0\ncpu0 100 0 100 375 75 0 0 0 0 0\ncpu1 100 0 100 375 75 0 0 0 0 0\n"


# ---- CPU -------------------------------------------------------------------
def test_cpu_percent_uses_deltas_not_cumulative(tmp_path):
    write(tmp_path, "stat", STAT_A)
    a = c.read_cpu_times(str(tmp_path))
    write(tmp_path, "stat", STAT_B)
    b = c.read_cpu_times(str(tmp_path))
    # total delta = 1300-1000 = 300, idle delta (idle+iowait) = 900-800 = 100 -> 200/300 busy
    assert c.cpu_percent(a["cpu"], b["cpu"]) == pytest.approx(200 / 3)
    assert c.cpu_percent(a["cpu0"], b["cpu0"]) == pytest.approx(200 / 3)   # core: 100 busy of 150
    # the since-boot figure (400 busy of 1300 = 30.8%) must NOT be what we report
    assert c.cpu_percent(c.CpuTimes(0, 0), b["cpu"]) == pytest.approx(100 * 400 / 1300)
    assert c.cpu_percent(a["cpu"], b["cpu"]) != pytest.approx(100 * 400 / 1300)


@pytest.mark.parametrize("prev,curr", [
    (c.CpuTimes(100, 50), c.CpuTimes(100, 50)),    # no time elapsed
    (c.CpuTimes(100, 50), c.CpuTimes(90, 40)),     # counter went backwards
    (c.CpuTimes(100, 50), c.CpuTimes(110, 80)),    # idle grew more than total
    (None, c.CpuTimes(1, 1)),
    (c.CpuTimes(1, 1), None),
])
def test_cpu_percent_returns_none_when_not_computable(prev, curr):
    assert c.cpu_percent(prev, curr) is None


def test_cpu_times_malformed_and_missing(tmp_path):
    assert c.read_cpu_times(str(tmp_path)) is None                # no /proc/stat
    write(tmp_path, "stat", "cpu abc def\ncpu0 1 2\nintr 5\n")
    assert c.read_cpu_times(str(tmp_path)) is None                # nothing parseable


# ---- memory ----------------------------------------------------------------
MEMINFO = "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\n"


def test_memory_calculation(tmp_path):
    write(tmp_path, "meminfo", MEMINFO)
    m = c.read_memory(str(tmp_path))
    assert (m.total, m.available, m.used) == (1000 * 1024, 400 * 1024, 600 * 1024)
    assert m.percent == pytest.approx(60.0)
    assert m.swap_used == 50 * 1024 and m.swap_percent == pytest.approx(25.0)


def test_memory_missing_available_is_none_not_guessed(tmp_path):
    write(tmp_path, "meminfo", "MemTotal: 1000 kB\nMemFree: 100 kB\n")
    m = c.read_memory(str(tmp_path))
    assert m.available is None and m.used is None and m.percent is None
    assert m.swap_total is None


def test_no_swap_has_no_percent(tmp_path):
    write(tmp_path, "meminfo", MEMINFO.replace("SwapTotal: 200", "SwapTotal: 0").replace("SwapFree: 150", "SwapFree: 0"))
    m = c.read_memory(str(tmp_path))
    assert m.swap_total == 0 and m.swap_percent is None


def test_memory_unreadable(tmp_path):
    assert c.read_memory(str(tmp_path)) is None


# ---- loadavg / uptime ------------------------------------------------------
def test_loadavg_and_uptime(tmp_path):
    write(tmp_path, "loadavg", "0.10 0.20 0.30 1/100 999\n")
    write(tmp_path, "uptime", "123.45 99.0\n")
    assert c.read_loadavg(str(tmp_path)) == (0.10, 0.20, 0.30)
    assert c.read_uptime(str(tmp_path)) == 123.45


def test_loadavg_uptime_malformed_or_missing(tmp_path):
    assert c.read_loadavg(str(tmp_path)) is None and c.read_uptime(str(tmp_path)) is None
    write(tmp_path, "loadavg", "garbage")
    write(tmp_path, "uptime", "")
    assert c.read_loadavg(str(tmp_path)) is None and c.read_uptime(str(tmp_path)) is None


# ---- disk ------------------------------------------------------------------
def fake_statvfs(blocks, bfree, bavail):
    return SimpleNamespace(f_blocks=blocks, f_bfree=bfree, f_bavail=bavail, f_frsize=1000)


def test_disk_percent_matches_df_and_filters_pseudo(tmp_path, monkeypatch):
    write(tmp_path, "mounts", "/dev/sda1 / ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n"
                              "proc /proc proc rw 0 0\n/dev/sdb1 /data xfs rw 0 0\n"
                              "/dev/sdc1 /locked ext4 rw 0 0\n")

    def statvfs(path):
        if path == "/locked":
            raise PermissionError
        return fake_statvfs(1000, 300, 200) if path == "/" else fake_statvfs(1000, 50, 50)
    monkeypatch.setattr(os, "statvfs", statvfs)
    disks = c.read_disks(str(tmp_path))
    assert [d.mount for d in disks] == ["/", "/data"]       # pseudo + unreadable skipped
    root = disks[0]
    assert root.used == 700_000 and root.free == 200_000
    assert root.percent == pytest.approx(100 * 700 / 900)    # used / (used + avail), like df
    assert disks[1].percent == pytest.approx(100 * 950 / 1000)


def test_disk_mounts_unreadable(tmp_path):
    assert c.read_disks(str(tmp_path)) is None


# ---- network ---------------------------------------------------------------
NETDEV = ("Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
          "  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n"
          "  bad: 1 2 3\n")


def test_network_parsing_skips_malformed(tmp_path):
    write(tmp_path, "net/dev", NETDEV)
    ifaces = c.read_network(str(tmp_path))
    assert len(ifaces) == 1
    i = ifaces[0]
    assert (i.name, i.rx_bytes, i.rx_errors, i.rx_dropped, i.tx_bytes, i.tx_errors, i.tx_dropped) == ("eth0", 1000, 1, 2, 2000, 3, 4)


def test_network_missing(tmp_path):
    assert c.read_network(str(tmp_path)) is None


# ---- processes -------------------------------------------------------------
def stat_line(pid, comm, utime, stime, rss):
    # fields after ')': state ppid ... ; utime is idx 11, stime idx 12, rss idx 21
    rest = ["S"] + ["0"] * 10 + [str(utime), str(stime)] + ["0"] * 8 + [str(rss)] + ["0"] * 5
    return f"{pid} ({comm}) " + " ".join(rest) + "\n"


def test_process_comm_with_spaces_and_parens(tmp_path):
    write(tmp_path, "10/stat", stat_line(10, "my (weird) app", 30, 20, 100))
    s = c.sample_processes(str(tmp_path))[10]
    assert s.name == "my (weird) app" and s.ticks == 50
    assert s.rss_bytes == 100 * os.sysconf("SC_PAGE_SIZE")


def test_unreadable_and_garbage_processes_are_skipped(tmp_path):
    write(tmp_path, "10/stat", "garbage")
    write(tmp_path, "11/stat", stat_line(11, "ok", 1, 1, 1))
    (tmp_path / "12").mkdir()                      # vanished: no stat file
    write(tmp_path, "self/stat", "ignored")        # non-numeric entries ignored
    assert set(c.sample_processes(str(tmp_path))) == {11}


def test_top_processes_cpu_math_and_new_process_not_zero():
    def mk(pid, t, rss=0):
        return c.ProcSample(pid, f"p{pid}", t, rss)

    prev = {1: mk(1, 100), 2: mk(2, 100)}
    curr = {1: mk(1, 150), 2: mk(2, 100), 3: mk(3, 500)}   # 3 appeared mid-interval
    top = c.top_processes(prev, curr, elapsed=1.0, mem_total=1000, n=5, clk_tck=100)
    assert [p.pid for p in top] == [1, 2]                    # pid 3 omitted, not shown as 0%
    assert top[0].cpu_percent == pytest.approx(50.0)         # 50 ticks / 100 Hz / 1 s


def test_top_processes_sorted_by_mem():
    def mk(pid, t, rss):
        return c.ProcSample(pid, f"p{pid}", t, rss)

    prev = {1: mk(1, 0, 10), 2: mk(2, 0, 10)}
    curr = {1: mk(1, 10, 100), 2: mk(2, 0, 900)}
    top = c.top_processes(prev, curr, 1.0, 1000, sort="mem", clk_tck=100)
    assert [p.pid for p in top] == [2, 1] and top[0].mem_percent == pytest.approx(90.0)


# ---- collect() end to end on a fake /proc ----------------------------------
def build_fake_proc(root):
    write(root, "stat", STAT_A)
    write(root, "meminfo", MEMINFO)
    write(root, "loadavg", "1.00 0.50 0.25 1/1 1\n")
    write(root, "uptime", "3600.0 0\n")
    write(root, "net/dev", NETDEV)
    write(root, "mounts", "")
    write(root, "10/stat", stat_line(10, "worker", 0, 0, 10))


def test_collect_computes_rates_between_samples(tmp_path):
    build_fake_proc(tmp_path)

    def fake_sleep(_):  # the "system" advances while we sleep
        write(tmp_path, "stat", STAT_B)
        write(tmp_path, "10/stat", stat_line(10, "worker", 50, 0, 10))
    ticks = iter([0.0, 2.0])
    snap = c.collect(2.0, proc=str(tmp_path), sleep=fake_sleep, clock=lambda: next(ticks))
    assert snap.cpu_percent == pytest.approx(200 / 3)
    assert snap.cpu_per_core == [pytest.approx(200 / 3)] * 2 and snap.cpu_count == 2
    assert snap.top_cpu[0].cpu_percent == pytest.approx(100.0 * 50 / os.sysconf("SC_CLK_TCK") / 2.0)
    assert snap.process_count == 1 and snap.unavailable == []


def test_collect_on_empty_proc_reports_unavailable_not_zero(tmp_path):
    snap = c.collect(0.0, proc=str(tmp_path), sleep=lambda _: None)
    assert snap.cpu_percent is None and snap.memory is None and snap.loadavg is None
    assert snap.process_count is None
    assert {"cpu_percent", "memory", "loadavg", "uptime_seconds", "network", "disks"} <= set(snap.unavailable)
