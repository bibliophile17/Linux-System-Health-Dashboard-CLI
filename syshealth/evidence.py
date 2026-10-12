"""Extra read-only evidence for diagnostics: disk I/O, sockets, pressure, OOM kills, failed units.

Everything here is read-only. The only external programs ever run are the two fixed,
allowlisted commands in ``_run_allowlisted`` (no shell, no user-controlled arguments).
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

from .collectors import PROC, NetIface, Snapshot, _read, collect, read_network

SYS = "/sys"
TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
              "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}


# ---------------------------------------------------------------- disk I/O ---

@dataclass(frozen=True)
class DiskStat:
    reads: int
    writes: int
    sectors_read: int
    sectors_written: int
    read_ms: int
    write_ms: int
    io_ms: int          # time the device had I/O in flight


@dataclass(frozen=True)
class DiskIORate:
    device: str
    util_percent: float
    read_bytes_per_s: float
    write_bytes_per_s: float
    iops: float
    await_ms: Optional[float]   # None when no I/O completed in the window


def read_diskstats(proc: str = PROC, sysroot: str = SYS) -> Optional[dict[str, DiskStat]]:
    text = _read(f"{proc}/diskstats")
    if text is None:
        return None
    have_sys_block = os.path.isdir(f"{sysroot}/block")
    out: dict[str, DiskStat] = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) < 13 or f[2].startswith(("loop", "ram", "zram")):
            continue
        if have_sys_block and not os.path.exists(f"{sysroot}/block/{f[2]}"):
            continue            # a partition: its whole disk is already counted
        try:
            v = [int(x) for x in f[3:13]]
        except ValueError:
            continue
        out[f[2]] = DiskStat(v[0], v[4], v[2], v[6], v[3], v[7], v[9])
    return out


def disk_io_rates(prev: Optional[dict[str, DiskStat]], curr: Optional[dict[str, DiskStat]],
                  elapsed: float) -> Optional[list[DiskIORate]]:
    if prev is None or curr is None or elapsed <= 0:
        return None
    rates = []
    for dev, c in curr.items():
        p = prev.get(dev)
        if p is None:
            continue
        d = {k: getattr(c, k) - getattr(p, k) for k in c.__dataclass_fields__}
        if min(d.values()) < 0:                 # counter reset or wrap: skip rather than guess
            continue
        ios = d["reads"] + d["writes"]
        rates.append(DiskIORate(
            device=dev,
            util_percent=min(100.0, 100.0 * d["io_ms"] / (elapsed * 1000.0)),
            read_bytes_per_s=d["sectors_read"] * 512 / elapsed,
            write_bytes_per_s=d["sectors_written"] * 512 / elapsed,
            iops=ios / elapsed,
            await_ms=(d["read_ms"] + d["write_ms"]) / ios if ios else None))
    return sorted(rates, key=lambda r: r.device)


# ----------------------------------------------------------------- sockets ---

@dataclass(frozen=True)
class Listener:
    address: str
    port: int

    @property
    def wildcard(self) -> bool:
        return self.address in ("0.0.0.0", "::")


@dataclass(frozen=True)
class SocketSummary:
    listeners: list[Listener]
    states: dict[str, int]       # TCP state name -> count (IPv4 + IPv6)


def _parse_addr(hexaddr: str) -> str:
    raw = bytes.fromhex(hexaddr)
    if len(raw) not in (4, 16):
        raise ValueError("bad address length")
    # /proc prints each 32-bit word in host (little-endian) order
    return str(ipaddress.ip_address(b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))))


def read_sockets(proc: str = PROC) -> Optional[SocketSummary]:
    listeners: list[Listener] = []
    states: dict[str, int] = {}
    readable = False
    for fname in ("net/tcp", "net/tcp6"):
        text = _read(f"{proc}/{fname}")
        if text is None:
            continue
        readable = True
        for line in text.splitlines()[1:]:
            f = line.split()
            if len(f) < 4:
                continue
            state = TCP_STATES.get(f[3].upper())
            if state is None:
                continue
            states[state] = states.get(state, 0) + 1
            if state == "LISTEN":
                try:
                    host, _, port = f[1].partition(":")
                    listeners.append(Listener(_parse_addr(host), int(port, 16)))
                except ValueError:
                    continue
    if not readable:
        return None
    return SocketSummary(sorted(listeners, key=lambda lst: (lst.port, lst.address)), states)


# ---------------------------------------------------- pressure / OOM / misc ---

@dataclass(frozen=True)
class Pressure:
    some_avg10: float            # % of the last 10 s in which at least one task was stalled
    full_avg10: Optional[float]  # % in which ALL non-idle tasks were stalled (None for cpu)


_AVG10 = re.compile(r"avg10=([0-9.]+)")


def read_pressure(proc: str = PROC) -> Optional[dict[str, Pressure]]:
    """PSI (Linux >= 4.20). None when the kernel does not expose it."""
    out: dict[str, Pressure] = {}
    for res in ("cpu", "memory", "io"):
        text = _read(f"{proc}/pressure/{res}")
        if text is None:
            continue
        vals: dict[str, float] = {}
        for line in text.splitlines():
            kind, _, rest = line.partition(" ")
            m = _AVG10.search(rest)
            if m and kind in ("some", "full"):
                vals[kind] = float(m.group(1))
        if "some" in vals:
            out[res] = Pressure(vals["some"], vals.get("full"))
    return out or None


def read_oom_kills(proc: str = PROC) -> Optional[int]:
    """Cumulative OOM-killer invocations since boot (/proc/vmstat oom_kill, Linux >= 4.13)."""
    text = _read(f"{proc}/vmstat")
    if text is None:
        return None
    for line in text.splitlines():
        k, _, v = line.partition(" ")
        if k == "oom_kill":
            try:
                return int(v)
            except ValueError:
                return None
    return None


# ------------------------------------------- allowlisted external commands ---

_SYSTEMCTL_FAILED = ["systemctl", "--failed", "--plain", "--no-legend", "--no-pager"]


def _journal_cmd(n: int) -> list[str]:
    return ["journalctl", "-p", "err", "-n", str(int(n)), "--no-pager", "-o", "short-iso", "-q"]


def _run_allowlisted(argv: list[str], timeout: float = 3.0) -> Optional[str]:
    """Run one of the fixed read-only commands. None if unavailable, denied or timed out."""
    allowed = argv == _SYSTEMCTL_FAILED or (argv[:1] == ["journalctl"] and argv[:3] == ["journalctl", "-p", "err"]
                                            and argv[3] == "-n" and argv[4].isdigit())
    if not allowed:
        raise ValueError(f"command not allowlisted: {argv!r}")
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, shell=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def parse_failed_units(text: str) -> list[str]:
    units = []
    for line in text.splitlines():
        tok = line.split()
        if tok and tok[0] in ("●", "*"):
            tok = tok[1:]
        if tok:
            units.append(tok[0])
    return units


def read_failed_units() -> Optional[list[str]]:
    out = _run_allowlisted(_SYSTEMCTL_FAILED)
    return None if out is None else parse_failed_units(out)


_SECRET = re.compile(r"(?i)\b(pass(?:word|wd)?|token|secret|api[_-]?key|authorization)\b(\s*[=:]\s*|\s+)"
                     r"(?:(?:bearer|basic)\s+)?\S+")
_SCHEME = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")


def redact(line: str, max_len: int = 300) -> str:
    """Best-effort scrub of obvious credentials; journal text is untrusted, so logs stay opt-in."""
    line = _SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", line)
    return _SCHEME.sub(lambda m: f"{m.group(1)} [REDACTED]", line)[:max_len]


def read_journal_errors(n: int) -> Optional[list[str]]:
    """Last ``n`` error-priority journal lines, redacted. None if the journal is unreadable."""
    n = max(1, min(int(n), 200))
    out = _run_allowlisted(_journal_cmd(n))
    return None if out is None else [redact(ln) for ln in out.splitlines() if ln.strip()]


# ---------------------------------------------------------------- evidence ---

@dataclass
class Evidence:
    snap: Snapshot
    diskio: Optional[list[DiskIORate]] = None
    sockets: Optional[SocketSummary] = None
    pressure: Optional[dict[str, Pressure]] = None
    oom_kills: Optional[int] = None
    failed_units: Optional[list[str]] = None
    net_deltas: Optional[dict[str, dict[str, int]]] = None   # iface -> {"errors": n, "drops": n} in window
    commands_run: bool = False


def net_deltas(prev: Optional[list[NetIface]], curr: Optional[list[NetIface]]) -> Optional[dict[str, dict[str, int]]]:
    if prev is None or curr is None:
        return None
    before = {i.name: i for i in prev}
    out = {}
    for c in curr:
        p = before.get(c.name)
        if p is None:
            continue
        errs = (c.rx_errors - p.rx_errors) + (c.tx_errors - p.tx_errors)
        drops = (c.rx_dropped - p.rx_dropped) + (c.tx_dropped - p.tx_dropped)
        if errs >= 0 and drops >= 0:       # negative = counter reset: omit instead of guessing
            out[c.name] = {"errors": errs, "drops": drops}
    return out


def gather(interval: float = 1.0, top_n: int = 5, proc: str = PROC, sysroot: str = SYS,
           run_commands: bool = True, collect_fn: Callable[..., Snapshot] = collect) -> Evidence:
    """Sample once over ``interval`` seconds; rates cover the same window as the snapshot."""
    d0, n0 = read_diskstats(proc, sysroot), read_network(proc)
    snap = collect_fn(interval, top_n, proc=proc)
    d1 = read_diskstats(proc, sysroot)
    return Evidence(
        snap=snap, diskio=disk_io_rates(d0, d1, snap.interval), sockets=read_sockets(proc),
        pressure=read_pressure(proc), oom_kills=read_oom_kills(proc),
        failed_units=read_failed_units() if run_commands else None,
        net_deltas=net_deltas(n0, snap.network), commands_run=run_commands)
