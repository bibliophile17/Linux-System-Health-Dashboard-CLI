"""Read-only Linux metric collectors.

Design rules:
  * Every reader takes a ``proc`` root (default ``/proc``) so tests can point it
    at a fake tree.
  * A metric that cannot be read is ``None`` -- never ``0``.
  * Readers never raise for missing files, permission errors or malformed
    content; they return ``None`` / skip the entry instead.
  * Rates (CPU %) are computed from the difference of two samples.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

PROC = "/proc"

# Filesystem types that are not real storage; skipped in the disk report.
PSEUDO_FS = frozenset({
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "overlay",
    "squashfs", "securityfs", "debugfs", "tracefs", "configfs", "fusectl", "mqueue",
    "hugetlbfs", "pstore", "bpf", "autofs", "binfmt_misc", "nsfs", "ramfs",
    "efivarfs", "rpc_pipefs", "selinuxfs", "fuse.gvfsd-fuse", "fuse.lxcfs",
})


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:  # missing, permission denied, process vanished
        return None


# ---------------------------------------------------------------- CPU --------

@dataclass(frozen=True)
class CpuTimes:
    """Cumulative jiffies for one CPU line of /proc/stat."""
    total: int
    idle: int  # idle + iowait


def read_cpu_times(proc: str = PROC) -> Optional[dict[str, CpuTimes]]:
    """Return {"cpu": CpuTimes, "cpu0": CpuTimes, ...} or None if unreadable."""
    text = _read(f"{proc}/stat")
    if text is None:
        return None
    out: dict[str, CpuTimes] = {}
    for line in text.splitlines():
        if not line.startswith("cpu"):
            continue
        parts = line.split()
        try:
            vals = [int(x) for x in parts[1:9]]  # user..steal; guest is already in user
        except ValueError:
            continue
        if len(vals) < 4:
            continue
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        out[parts[0]] = CpuTimes(total=sum(vals), idle=idle)
    return out or None


def cpu_percent(prev: Optional[CpuTimes], curr: Optional[CpuTimes]) -> Optional[float]:
    """Busy percentage between two samples; None if it cannot be computed."""
    if prev is None or curr is None:
        return None
    dt = curr.total - prev.total
    di = curr.idle - prev.idle
    if dt <= 0 or di < 0 or di > dt:  # no time elapsed, counter reset, or garbage
        return None
    return 100.0 * (dt - di) / dt


# ------------------------------------------------------------- memory --------

@dataclass(frozen=True)
class Memory:
    total: Optional[int]
    available: Optional[int]
    used: Optional[int]
    percent: Optional[float]
    swap_total: Optional[int]
    swap_used: Optional[int]
    swap_percent: Optional[float]


def _meminfo(proc: str) -> Optional[dict[str, int]]:
    text = _read(f"{proc}/meminfo")
    if text is None:
        return None
    info: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        fields = rest.split()
        if not fields:
            continue
        try:
            info[key] = int(fields[0]) * (1024 if len(fields) > 1 and fields[1].lower() == "kb" else 1)
        except ValueError:
            continue
    return info


def read_memory(proc: str = PROC) -> Optional[Memory]:
    """used = MemTotal - MemAvailable (the kernel's estimate of reclaimable memory)."""
    info = _meminfo(proc)
    if info is None:
        return None
    total = info.get("MemTotal")
    avail = info.get("MemAvailable")  # absent on kernels < 3.14: we do not guess
    used = total - avail if total is not None and avail is not None else None
    pct = 100.0 * used / total if used is not None and total else None
    s_total = info.get("SwapTotal")
    s_free = info.get("SwapFree")
    s_used = s_total - s_free if s_total is not None and s_free is not None else None
    # Swap of 0 bytes is a real, known state ("no swap"), so its percentage is None.
    s_pct = 100.0 * s_used / s_total if s_used is not None and s_total else None
    return Memory(total, avail, used, pct, s_total, s_used, s_pct)


# ----------------------------------------------------- load / uptime --------

def read_loadavg(proc: str = PROC) -> Optional[tuple[float, float, float]]:
    text = _read(f"{proc}/loadavg")
    try:
        a, b, c = text.split()[:3]  # type: ignore[union-attr]
        return float(a), float(b), float(c)
    except (AttributeError, ValueError):
        return None


def read_uptime(proc: str = PROC) -> Optional[float]:
    text = _read(f"{proc}/uptime")
    try:
        return float(text.split()[0])  # type: ignore[union-attr]
    except (AttributeError, ValueError, IndexError):
        return None


# --------------------------------------------------------------- disk --------

@dataclass(frozen=True)
class DiskUsage:
    mount: str
    fstype: str
    total: int
    used: int
    free: int
    percent: float  # same definition as df: used / (used + available to unprivileged)


def read_disks(proc: str = PROC) -> Optional[list[DiskUsage]]:
    text = _read(f"{proc}/mounts")
    if text is None:
        return None
    seen: set[str] = set()
    out: list[DiskUsage] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mount, fstype = parts[0], parts[1].replace("\\040", " "), parts[2]
        is_real_dev = dev.startswith("/") or ":" in dev  # block device or network share
        if fstype in PSEUDO_FS or mount in seen or not is_real_dev:
            continue
        try:
            st = os.statvfs(mount)
        except OSError:  # permission denied, stale NFS, unmounted meanwhile
            continue
        total = st.f_blocks * st.f_frsize
        if total == 0:
            continue
        free = st.f_bfree * st.f_frsize
        avail = st.f_bavail * st.f_frsize
        used = total - free
        denom = used + avail
        seen.add(mount)
        out.append(DiskUsage(mount, fstype, total, used, avail, 100.0 * used / denom if denom else 0.0))
    return out


# ------------------------------------------------------------ network --------

@dataclass(frozen=True)
class NetIface:
    name: str
    rx_bytes: int
    rx_packets: int
    rx_errors: int
    rx_dropped: int
    tx_bytes: int
    tx_packets: int
    tx_errors: int
    tx_dropped: int


def read_network(proc: str = PROC) -> Optional[list[NetIface]]:
    text = _read(f"{proc}/net/dev")
    if text is None:
        return None
    out: list[NetIface] = []
    for line in text.splitlines()[2:]:
        name, sep, rest = line.partition(":")
        f = rest.split()
        if not sep or len(f) < 16:
            continue
        try:
            n = [int(x) for x in f[:16]]
        except ValueError:
            continue
        out.append(NetIface(name.strip(), n[0], n[1], n[2], n[3], n[8], n[9], n[10], n[11]))
    return out


# ---------------------------------------------------------- processes --------

@dataclass(frozen=True)
class ProcSample:
    pid: int
    name: str
    ticks: int          # utime + stime
    rss_bytes: int


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    name: str
    cpu_percent: Optional[float]
    mem_percent: Optional[float]


def _read_proc_sample(proc: str, pid: int, page: int) -> Optional[ProcSample]:
    stat = _read(f"{proc}/{pid}/stat")
    if stat is None:
        return None
    # comm may contain spaces and ')' so split on the LAST ')'.
    lp, rp = stat.find("("), stat.rfind(")")
    if lp < 0 or rp < lp:
        return None
    rest = stat[rp + 2:].split()
    try:
        ticks = int(rest[11]) + int(rest[12])  # utime, stime (fields 14,15)
        rss_pages = int(rest[21])              # rss (field 24)
    except (IndexError, ValueError):
        return None
    return ProcSample(pid, stat[lp + 1:rp], ticks, rss_pages * page)


def list_pids(proc: str = PROC) -> Optional[list[int]]:
    try:
        return [int(n) for n in os.listdir(proc) if n.isdigit()]
    except OSError:
        return None


def sample_processes(proc: str = PROC) -> dict[int, ProcSample]:
    page = os.sysconf("SC_PAGE_SIZE")
    out: dict[int, ProcSample] = {}
    for pid in list_pids(proc) or []:
        s = _read_proc_sample(proc, pid, page)
        if s is not None:  # vanished or unreadable processes are skipped
            out[pid] = s
    return out


def top_processes(prev: dict[int, ProcSample], curr: dict[int, ProcSample], elapsed: float,
                  mem_total: Optional[int], n: int = 5, sort: str = "cpu",
                  clk_tck: Optional[int] = None) -> list[ProcInfo]:
    """CPU% is relative to one core (100% == one fully busy core), like top.

    Only processes present in BOTH samples get a CPU figure; others are skipped,
    so a process that appeared mid-interval is never reported as 0%.
    """
    tck = clk_tck or os.sysconf("SC_CLK_TCK")
    rows: list[ProcInfo] = []
    for pid, c in curr.items():
        p = prev.get(pid)
        if p is None or elapsed <= 0 or c.ticks < p.ticks:
            continue
        cpu = 100.0 * (c.ticks - p.ticks) / tck / elapsed
        mem = 100.0 * c.rss_bytes / mem_total if mem_total else None
        rows.append(ProcInfo(pid, c.name, cpu, mem))
    key = (lambda r: r.mem_percent or 0.0) if sort == "mem" else (lambda r: r.cpu_percent or 0.0)
    rows.sort(key=key, reverse=True)
    return rows[:n]


# ----------------------------------------------------------- snapshot --------

@dataclass
class Snapshot:
    timestamp: float
    hostname: str
    kernel: str
    interval: float
    cpu_percent: Optional[float]
    cpu_per_core: list[Optional[float]]
    cpu_count: Optional[int]
    loadavg: Optional[tuple[float, float, float]]
    uptime_seconds: Optional[float]
    memory: Optional[Memory]
    disks: Optional[list[DiskUsage]]
    network: Optional[list[NetIface]]
    process_count: Optional[int]
    top_cpu: list[ProcInfo] = field(default_factory=list)
    top_mem: list[ProcInfo] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)


def collect(interval: float = 1.0, top_n: int = 5, proc: str = PROC,
            sleep=time.sleep, clock=time.monotonic) -> Snapshot:
    """Take two samples ``interval`` seconds apart and compute rates between them."""
    c0, p0, t0 = read_cpu_times(proc), sample_processes(proc), clock()
    sleep(interval)
    c1, p1, t1 = read_cpu_times(proc), sample_processes(proc), clock()
    elapsed = t1 - t0

    cores = sorted((k for k in (c1 or {}) if k != "cpu"), key=lambda k: int(k[3:]))
    per_core = [cpu_percent((c0 or {}).get(k), (c1 or {}).get(k)) for k in cores]
    mem = read_memory(proc)
    mem_total = mem.total if mem else None
    uname = os.uname()

    snap = Snapshot(
        timestamp=time.time(), hostname=uname.nodename, kernel=f"{uname.sysname} {uname.release}",
        interval=elapsed,
        cpu_percent=cpu_percent((c0 or {}).get("cpu"), (c1 or {}).get("cpu")),
        cpu_per_core=per_core, cpu_count=len(cores) or None,
        loadavg=read_loadavg(proc), uptime_seconds=read_uptime(proc),
        memory=mem, disks=read_disks(proc), network=read_network(proc),
        process_count=len(p1) if p1 else None,
        top_cpu=top_processes(p0, p1, elapsed, mem_total, top_n, "cpu"),
        top_mem=top_processes(p0, p1, elapsed, mem_total, top_n, "mem"),
    )
    for name in ("cpu_percent", "loadavg", "uptime_seconds", "memory", "disks", "network", "process_count"):
        if getattr(snap, name) is None:
            snap.unavailable.append(name)
    return snap
