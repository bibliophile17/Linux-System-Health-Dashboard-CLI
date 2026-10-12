"""Read-only diagnostic rules.

Each rule turns evidence into a Finding with strictly separated parts:
  observations  - measured facts, with the numbers that support them
  hypotheses    - possible explanations; NEVER stated as established causes
  follow_up     - read-only commands a human can run to confirm or refute them
  limitations   - what this check cannot see
Nothing here executes follow-up commands, and no rule modifies the system.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Callable, Optional

from .config import Config
from .evidence import Evidence
from .render import human_bytes

RANK = {"ok": 0, "unknown": 0, "info": 1, "warning": 2, "critical": 3}

# Heuristic, documented in the README; not configurable yet.
IO_UTIL_WARN, IO_UTIL_CRIT = 70.0, 90.0
PSI_WARN, PSI_CRIT = 10.0, 30.0          # "some" avg10 percent
CLOSE_WAIT_WARN, TIME_WAIT_WARN, SYN_RECV_WARN = 100, 5000, 100
DOMINANT_PROCESS_SHARE = 0.5             # one process using >= half of the busy CPU
DOMINANT_MEMORY_SHARE = 30.0             # one process holding >= 30% of RAM


@dataclass
class Finding:
    id: str
    title: str
    status: str                       # ok | info | warning | critical | unknown
    summary: str
    observations: list[str] = field(default_factory=list)
    why_it_matters: str = ""
    hypotheses: list[str] = field(default_factory=list)
    follow_up: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _worst(*statuses: str) -> str:
    return max(statuses, key=RANK.__getitem__)


def _level(value: Optional[float], warn: float, crit: float) -> str:
    return "ok" if value is None else "critical" if value >= crit else "warning" if value >= warn else "ok"


def _unknown(fid: str, title: str, what: str, limitation: str) -> Finding:
    return Finding(fid, title, "unknown", f"Could not assess: {what}.", limitations=[limitation])


def _psi_obs(ev: Evidence, res: str) -> tuple[list[str], str]:
    p = (ev.pressure or {}).get(res)
    if p is None:
        return [], "ok"
    full = "" if p.full_avg10 is None else f", full {p.full_avg10:.1f}%"
    return ([f"{res} pressure (PSI, last 10 s): some {p.some_avg10:.1f}%{full} of time stalled"],
            _level(p.some_avg10, PSI_WARN, PSI_CRIT))


# ------------------------------------------------------------------- CPU ----

def diag_cpu(ev: Evidence, cfg: Config) -> Finding:
    s = ev.snap
    lpc = s.loadavg[0] / s.cpu_count if s.loadavg and s.cpu_count else None
    if s.cpu_percent is None and lpc is None:
        return _unknown("cpu", "High CPU usage", "CPU utilisation and load average were unreadable",
                        "/proc/stat and /proc/loadavg could not be read.")
    w, c = cfg.thresholds["cpu_percent"]
    lw, lc = cfg.thresholds["load_per_core"]
    psi_obs, psi_status = _psi_obs(ev, "cpu")
    status = _worst(_level(s.cpu_percent, w, c), _level(lpc, lw, lc), psi_status)

    obs = []
    if s.cpu_percent is not None:
        obs.append(f"CPU busy {s.cpu_percent:.1f}% averaged over {s.interval:.1f}s (warn {w:g}, crit {c:g})")
    if lpc is not None:
        obs.append(f"1-min load average {s.loadavg[0]:.2f} on {s.cpu_count} CPUs = {lpc:.2f} per CPU "
                   f"(warn {lw:g}, crit {lc:g})")
    obs += psi_obs
    obs += [f"top CPU process: {p.name} (pid {p.pid}) {p.cpu_percent:.1f}% of one core" for p in s.top_cpu[:3]
            if p.cpu_percent is not None]

    if status == "ok":
        return Finding("cpu", "High CPU usage", "ok", "CPU usage and load are within thresholds.", obs[:2])

    hyp = []
    if s.cpu_percent and s.cpu_count and s.top_cpu and s.top_cpu[0].cpu_percent is not None:
        share = s.top_cpu[0].cpu_percent / (s.cpu_percent * s.cpu_count)
        if share >= DOMINANT_PROCESS_SHARE:
            hyp.append(f"A single process ({s.top_cpu[0].name}) may account for most of the CPU "
                       f"(~{share:.0%} of busy time); it has not been confirmed to be the cause.")
        else:
            hyp.append("CPU use appears spread across many processes rather than one dominant consumer.")
    if lpc is not None and lpc >= lw and (s.cpu_percent or 0) < w:
        hyp.append("Load is high while CPU is not: tasks may be blocked on I/O or locks rather than computing.")
    return Finding(
        "cpu", "High CPU usage", status,
        "CPU utilisation, load, or CPU pressure exceeds thresholds.", obs,
        "Sustained CPU saturation delays every runnable task; latency-sensitive services see scheduling "
        "delay before throughput visibly drops.", hyp,
        ["top -b -n 1 -o %CPU | head -15", "vmstat 1 5", "pidstat -u 1 5   # needs the sysstat package",
         "cat /proc/pressure/cpu"],
        [f"CPU% is an average over {s.interval:.1f}s; shorter bursts are invisible.",
         "Only process names are collected (no command lines), by design.",
         "Processes hidden by hidepid or in other PID namespaces are not visible."])


# ---------------------------------------------------------------- memory ----

def diag_memory(ev: Evidence, cfg: Config) -> Finding:
    s, m = ev.snap, ev.snap.memory
    if m is None or (m.percent is None and m.swap_percent is None):
        return _unknown("memory", "Memory pressure", "memory figures were unreadable",
                        "/proc/meminfo could not be read or lacks MemAvailable.")
    w, c = cfg.thresholds["memory_percent"]
    sw, sc = cfg.thresholds["swap_percent"]
    psi_obs, psi_status = _psi_obs(ev, "memory")
    status = _worst(_level(m.percent, w, c), _level(m.swap_percent, sw, sc), psi_status)
    if status == "ok" and ev.oom_kills:
        status = "info"

    obs = []
    if m.percent is not None:
        obs.append(f"RAM used {m.percent:.1f}% ({human_bytes(m.used)} of {human_bytes(m.total)}, "
                   f"{human_bytes(m.available)} available; warn {w:g}, crit {c:g})")
    if m.swap_total:
        obs.append(f"swap used {m.swap_percent:.1f}% ({human_bytes(m.swap_used)} of {human_bytes(m.swap_total)})")
    elif m.swap_total == 0:
        obs.append("no swap configured")
    if ev.oom_kills is not None:
        obs.append(f"OOM-killer invocations since boot: {ev.oom_kills}")
    obs += psi_obs
    obs += [f"top memory process: {p.name} (pid {p.pid}) {p.mem_percent:.1f}% of RAM"
            for p in s.top_mem[:3] if p.mem_percent is not None]

    if status == "ok":
        return Finding("memory", "Memory pressure", "ok", "Memory usage is within thresholds.", obs[:2])

    hyp = []
    if s.top_mem and s.top_mem[0].mem_percent and s.top_mem[0].mem_percent >= DOMINANT_MEMORY_SHARE:
        t = s.top_mem[0]
        hyp.append(f"{t.name} holds {t.mem_percent:.0f}% of RAM. Whether this is a leak or an intended working "
                   "set cannot be determined from a single snapshot.")
    if m.swap_percent is not None and m.swap_percent >= sw:
        hyp.append("Memory demand may have exceeded RAM at some point, pushing pages to swap; "
                   "swapped pages are slow to bring back.")
    if ev.oom_kills:
        hyp.append("A process may have been killed by the kernel OOM killer at some time since boot; "
                   "the counter does not say when or which process.")
    return Finding(
        "memory", "Memory pressure", status,
        "Memory, swap, or memory-pressure indicators need attention." if status != "info"
        else "Memory is currently fine, but OOM kills were recorded since boot.", obs,
        "When available memory runs out the kernel reclaims cache, swaps, or kills processes, any of which "
        "can cause latency spikes or unexpected service termination.", hyp,
        ["free -h", "ps -eo pid,comm,rss --sort=-rss | head -10", "cat /proc/pressure/memory",
         "dmesg | grep -i 'out of memory'   # may need privileges"],
        ["MemAvailable is a kernel estimate, not a guarantee.",
         "Per-process RSS counts shared pages in every process, so percentages can sum above 100.",
         "The OOM counter is cumulative since boot and carries no timestamps."])


# ------------------------------------------------------------ disk space ----

def diag_disk_space(ev: Evidence, cfg: Config) -> Finding:
    disks = ev.snap.disks
    if disks is None:
        return _unknown("disk_space", "Low disk space", "mounted filesystems were unreadable",
                        "/proc/mounts could not be read.")
    w, c = cfg.thresholds["disk_percent"]
    flagged = [d for d in disks if d.percent >= w]
    if not flagged:
        top = max(disks, key=lambda d: d.percent, default=None)
        obs = [f"fullest filesystem: {top.mount} at {top.percent:.1f}%"] if top else ["no real filesystems found"]
        return Finding("disk_space", "Low disk space", "ok", "All filesystems are below the warning threshold.", obs)
    status = "critical" if any(d.percent >= c for d in flagged) else "warning"
    mount = max(flagged, key=lambda d: d.percent).mount
    return Finding(
        "disk_space", "Low disk space", status, f"{len(flagged)} filesystem(s) at or above {w:g}% used.",
        [f"{d.mount} ({d.fstype}): {d.percent:.1f}% used, {human_bytes(d.free)} free of {human_bytes(d.total)}"
         for d in sorted(flagged, key=lambda d: -d.percent)],
        "A full filesystem makes writes fail (logs, databases, temp files) and can cascade into service failures.",
        ["Growth from logs, core dumps, caches or temporary files is a common cause, but which directory "
         "is responsible has not been measured."],
        ["df -h", "df -i", f"du -xh --max-depth=1 {shlex.quote(mount)} 2>/dev/null | sort -h | tail -15",
         "lsof +L1   # deleted files still held open"],
        ["Inode exhaustion is not checked here (use df -i).", "Space held by deleted-but-open files appears as used "
         "but has no visible path.", "Percent follows df: used / (used + space available to non-root)."])


# ----------------------------------------------------------- disk I/O -------

def diag_disk_io(ev: Evidence, cfg: Config) -> Finding:
    if ev.diskio is None:
        return _unknown("disk_io", "Disk I/O bottleneck", "per-device I/O counters were unreadable",
                        "/proc/diskstats could not be read or a second sample was impossible.")
    psi_obs, psi_status = _psi_obs(ev, "io")
    busiest = sorted(ev.diskio, key=lambda r: -r.util_percent)
    top = busiest[0] if busiest else None
    status = _worst(_level(top.util_percent if top else None, IO_UTIL_WARN, IO_UTIL_CRIT), psi_status)
    obs = []
    for r in busiest[:3]:
        aw = "n/a" if r.await_ms is None else f"{r.await_ms:.1f} ms"
        obs.append(f"{r.device}: {r.util_percent:.0f}% busy, read {human_bytes(r.read_bytes_per_s)}/s, "
                   f"write {human_bytes(r.write_bytes_per_s)}/s, {r.iops:.0f} IOPS, avg wait {aw}")
    obs += psi_obs
    if not obs:
        obs = ["no block devices found"]
    if status == "ok":
        return Finding("disk_io", "Disk I/O bottleneck", "ok", "No disk is near saturation.", obs[:2])
    hyp = ["A device that is busy for most of the window with high wait times may be saturated or slow.",
           "High busy-time with low throughput can indicate small random I/O or a degraded/virtualised device."]
    return Finding(
        "disk_io", "Disk I/O bottleneck", status, "A block device or I/O pressure indicator is high.", obs,
        "Saturated storage stalls processes in uninterruptible I/O wait, raising load and latency without raising CPU.",
        hyp, ["iostat -xz 1 5   # needs the sysstat package", "cat /proc/pressure/io",
              "ps -eo pid,stat,comm | awk '$2 ~ /D/'"],
        ["'Busy %' is not a reliable saturation measure for NVMe and other parallel devices.",
         "In containers or VMs the visible devices may not match the physical ones.",
         "Which process generates the I/O is not identified."])


# ---------------------------------------------------------- process count ---

def diag_process_count(ev: Evidence, cfg: Config) -> Finding:
    n = ev.snap.process_count
    if n is None:
        return _unknown("process_count", "High process count", "the process count was unreadable",
                        "The /proc directory listing failed.")
    w, c = cfg.thresholds["process_count"]
    status = _level(float(n), w, c)
    obs = [f"{n} processes visible (warn {w:g}, crit {c:g})"]
    if status == "ok":
        return Finding("process_count", "High process count", "ok", "Process count is within thresholds.", obs)
    return Finding(
        "process_count", "High process count", status, "The number of processes exceeds the threshold.", obs,
        "Runaway process creation can exhaust PIDs, memory and scheduler capacity.",
        ["Possible causes include runaway forking, accumulating zombie processes, or a legitimate many-worker "
         "workload; the data here cannot tell these apart."],
        ["ps -eo stat | cut -c1 | sort | uniq -c", "ps -eo ppid | sort | uniq -c | sort -rn | head",
         "cat /proc/sys/kernel/pid_max"],
        ["Counts processes, not threads.", "Process states (e.g. zombies) are not collected."])


# ------------------------------------------------------------- services -----

def diag_services(ev: Evidence, cfg: Config) -> Finding:
    if not ev.commands_run:
        return _unknown("services", "Unexpected service termination",
                        "service state was not queried (commands disabled)",
                        "Run without --no-commands to query systemd.")
    if ev.failed_units is None:
        return _unknown("services", "Unexpected service termination", "systemctl was unavailable or denied",
                        "systemd may not be present (containers, WSL1) or access was refused.")
    obs = [f"failed systemd units: {len(ev.failed_units)}"] + [f"  - {u}" for u in ev.failed_units[:10]]
    if len(ev.failed_units) > 10:
        obs.append(f"  ... and {len(ev.failed_units) - 10} more")
    if ev.oom_kills is not None:
        obs.append(f"OOM-killer invocations since boot: {ev.oom_kills}")
    if not ev.failed_units:
        return Finding("services", "Unexpected service termination", "info" if ev.oom_kills else "ok",
                       "No units are in the failed state.", obs)
    first = shlex.quote(ev.failed_units[0])
    return Finding(
        "services", "Unexpected service termination", "warning",
        f"{len(ev.failed_units)} systemd unit(s) are in a failed state.", obs,
        "A failed unit means a service exited abnormally and was not (or could not be) restarted.",
        ["A failed unit usually exited non-zero, was killed by a signal (possibly the OOM killer), or hit its "
         "restart limit; the exit reason is not captured here."],
        ["systemctl --failed", f"systemctl status {first} --no-pager", f"journalctl -u {first} -n 50 --no-pager"],
        ["Only systemd units are covered.", "A service that crashed and restarted successfully does not appear.",
         "Reading the journal for the reason may require group membership or root."])


# ---------------------------------------------------- ports / connections ---

def diag_sockets(ev: Evidence, cfg: Config) -> Finding:
    sk = ev.sockets
    if sk is None:
        return _unknown("sockets", "Listening ports and connections", "TCP socket tables were unreadable",
                        "/proc/net/tcp and /proc/net/tcp6 could not be read.")
    st = sk.states
    wildcard = [f"{lst.address}:{lst.port}" for lst in sk.listeners if lst.wildcard]
    obs = [f"{len(sk.listeners)} TCP listening socket(s); {len(wildcard)} bound to all interfaces"]
    if wildcard:
        obs.append("all-interface listeners: " + ", ".join(wildcard[:10]) + (" ..." if len(wildcard) > 10 else ""))
    obs.append("connection states: " + (", ".join(f"{k}={v}" for k, v in sorted(st.items())) or "none"))
    hyp, flagged = [], False
    if st.get("CLOSE_WAIT", 0) >= CLOSE_WAIT_WARN:
        flagged = True
        hyp.append(f"{st['CLOSE_WAIT']} sockets in CLOSE_WAIT: the local application may not be closing sockets "
                   "after peers disconnect (possible leak or slow shutdown path).")
    if st.get("TIME_WAIT", 0) >= TIME_WAIT_WARN:
        flagged = True
        hyp.append(f"{st['TIME_WAIT']} sockets in TIME_WAIT: many short-lived connections may be opened and closed.")
    if st.get("SYN_RECV", 0) >= SYN_RECV_WARN:
        flagged = True
        hyp.append(f"{st['SYN_RECV']} sockets in SYN_RECV: a SYN flood or an overloaded accept queue is possible.")
    if not flagged:
        return Finding("sockets", "Listening ports and connections", "ok",
                       "No abnormal TCP connection-state counts.", obs)
    return Finding(
        "sockets", "Listening ports and connections", "warning", "TCP connection-state counts are unusually high.",
        obs, "Connection-state build-up can exhaust file descriptors, ports or accept queues.", hyp,
        ["ss -s", "ss -ltn", "ss -tan state close-wait | head", "cat /proc/sys/net/ipv4/ip_local_port_range"],
        ["TCP only: UDP sockets are not examined.", "Sockets are not attributed to processes (needs privileges).",
         f"Thresholds are heuristics (CLOSE_WAIT>={CLOSE_WAIT_WARN}, TIME_WAIT>={TIME_WAIT_WARN}, "
         f"SYN_RECV>={SYN_RECV_WARN}) and not tuned to your workload."])


# ------------------------------------------------------- interface errors ---

def diag_network_errors(ev: Evidence, cfg: Config) -> Finding:
    if ev.net_deltas is None or ev.snap.network is None:
        return _unknown("network_errors", "Network interface errors", "interface counters were unreadable",
                        "/proc/net/dev could not be read.")
    cumulative = {i.name: (i.rx_errors + i.tx_errors, i.rx_dropped + i.tx_dropped) for i in ev.snap.network}
    active = {k: v for k, v in ev.net_deltas.items() if v["errors"] or v["drops"]}
    historic = [k for k, (e, d) in cumulative.items() if (e or d) and k not in active]
    obs = [f"{k}: +{v['errors']} errors, +{v['drops']} drops during the {ev.snap.interval:.1f}s window "
           f"(since boot: {cumulative[k][0]} errors, {cumulative[k][1]} drops)" for k, v in sorted(active.items())]
    obs += [f"{k}: counters non-zero since boot ({cumulative[k][0]} errors, {cumulative[k][1]} drops) "
            "but unchanged in this window" for k in sorted(historic)]
    if not obs:
        return Finding("network_errors", "Network interface errors", "ok",
                       "No interface errors or drops observed.", ["all interface error/drop counters are zero"])
    status = "warning" if active else "info"
    iface = shlex.quote(sorted(active or historic)[0])
    return Finding(
        "network_errors", "Network interface errors", status,
        "Errors or drops are increasing on at least one interface." if active
        else "Interfaces show historic errors/drops, none in the sampled window.", obs,
        "Interface errors and drops mean packets were lost before reaching applications, causing retransmits or gaps.",
        ["Errors can point to cabling, driver or duplex problems; drops can point to receive-buffer overflow, "
         "CPU not servicing interrupts fast enough, or virtual-interface policy. None of these is confirmed."],
        [f"ip -s link show {iface}", f"ethtool -S {iface}   # may need privileges", "cat /proc/net/softnet_stat",
         "nstat -az | grep -i -E 'drop|err'"],
        ["Only one short window is sampled; compare repeated runs to see a trend.",
         "Counters can reset on driver reload, and virtual interfaces count drops differently.",
         "Loopback and virtual interfaces are included."])


RULES: list[Callable[[Evidence, Config], Finding]] = [
    diag_cpu, diag_memory, diag_disk_space, diag_disk_io, diag_process_count,
    diag_services, diag_sockets, diag_network_errors,
]


def run_diagnostics(ev: Evidence, cfg: Config) -> list[Finding]:
    """Run every rule; a bug in one rule is reported as 'unknown', never allowed to hide the others."""
    out = []
    for rule in RULES:
        try:
            out.append(rule(ev, cfg))
        except Exception as e:  # noqa: BLE001 - monitoring must keep going
            out.append(Finding(rule.__name__.removeprefix("diag_"), rule.__name__, "unknown",
                               f"Rule failed: {type(e).__name__}", limitations=[str(e)[:200]]))
    return out


def highest(findings: list[Finding]) -> str:
    return max((f.status for f in findings), key=RANK.__getitem__, default="ok")
