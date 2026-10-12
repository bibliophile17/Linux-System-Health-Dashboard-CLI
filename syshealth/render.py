"""Plain-text rendering (stdlib only). Colour is used only on a TTY."""

from __future__ import annotations

import datetime
from typing import Optional

from .collectors import Snapshot

FALLBACK = (70.0, 90.0)   # bar colour for bars with no configured metric
NA = "n/a"


class Style:
    def __init__(self, color: bool, thresholds: Optional[dict] = None):
        self.color = color
        self.thresholds = thresholds or {}

    def paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def level(self, pct: Optional[float], metric: Optional[str] = None) -> str:
        if pct is None:
            return "2"          # dim
        warn, crit = self.thresholds.get(metric, FALLBACK)
        return "31" if pct >= crit else "33" if pct >= warn else "32"


def human_bytes(n: Optional[float]) -> str:
    if n is None:
        return NA
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def human_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return NA
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    return f"{d}d {h}h {m}m" if d else f"{h}h {m}m"


def bar(pct: Optional[float], st: Style, width: int = 20, metric: Optional[str] = None) -> str:
    if pct is None:
        return f"{'?' * width}  {NA:>6}"
    pct_c = max(0.0, min(100.0, pct))
    filled = int(width * pct_c / 100)
    return st.paint("#" * filled + "-" * (width - filled), st.level(pct, metric)) + f" {pct:5.1f}%"


def _title(text: str, st: Style) -> str:
    return st.paint(f"== {text} ", "1;36")


def section_cpu(s: Snapshot, st: Style) -> list[str]:
    lines = [_title("CPU", st), f"  {'overall':<10}{bar(s.cpu_percent, st, metric='cpu_percent')}"]
    for i, p in enumerate(s.cpu_per_core):
        lines.append(f"  {'core ' + str(i):<10}{bar(p, st, metric='cpu_percent')}")
    if s.loadavg:
        lines.append(f"  {'load avg':<10}{s.loadavg[0]:.2f} {s.loadavg[1]:.2f} {s.loadavg[2]:.2f}"
                     f"  (cores: {s.cpu_count or NA})")
    else:
        lines.append(f"  {'load avg':<10}{NA}")
    return lines


def section_memory(s: Snapshot, st: Style) -> list[str]:
    m = s.memory
    lines = [_title("Memory", st)]
    if m is None:
        return lines + [f"  {NA} (could not read /proc/meminfo)"]
    ram_bar = bar(m.percent, st, metric="memory_percent")
    lines.append(f"  {'RAM':<10}{ram_bar}  {human_bytes(m.used)} used / {human_bytes(m.total)}"
                 f"  ({human_bytes(m.available)} available)")
    if m.swap_total == 0:
        lines.append(f"  {'swap':<10}none configured")
    else:
        swap_bar = bar(m.swap_percent, st, metric="swap_percent")
        lines.append(f"  {'swap':<10}{swap_bar}  {human_bytes(m.swap_used)} / {human_bytes(m.swap_total)}")
    return lines


def section_disk(s: Snapshot, st: Style) -> list[str]:
    lines = [_title("Disk", st)]
    if s.disks is None:
        return lines + [f"  {NA} (could not read /proc/mounts)"]
    lines.append(f"  {'mount':<22}{'type':<8}{'usage':<29}{'used':>11}{'free':>11}{'total':>11}")
    for d in s.disks:
        usage = bar(d.percent, st, metric="disk_percent")
        lines.append(f"  {d.mount[:21]:<22}{d.fstype[:7]:<8}{usage:<29}"
                     f"{human_bytes(d.used):>11}{human_bytes(d.free):>11}{human_bytes(d.total):>11}")
    return lines


def section_network(s: Snapshot, st: Style) -> list[str]:
    lines = [_title("Network (cumulative since boot)", st)]
    if s.network is None:
        return lines + [f"  {NA} (could not read /proc/net/dev)"]
    lines.append(f"  {'iface':<12}{'rx':>12}{'tx':>12}{'rx err':>9}{'tx err':>9}{'rx drop':>9}{'tx drop':>9}")
    for i in s.network:
        bad = i.rx_errors + i.tx_errors + i.rx_dropped + i.tx_dropped
        row = (f"  {i.name:<12}{human_bytes(i.rx_bytes):>12}{human_bytes(i.tx_bytes):>12}"
               f"{i.rx_errors:>9}{i.tx_errors:>9}{i.rx_dropped:>9}{i.tx_dropped:>9}")
        lines.append(st.paint(row, "33") if bad else row)
    return lines


def section_processes(s: Snapshot, st: Style, by: str = "cpu") -> list[str]:
    rows = s.top_cpu if by == "cpu" else s.top_mem
    lines = [_title(f"Top processes by {by.upper()} (CPU% of one core)", st),
             f"  {'PID':>7}  {'NAME':<22}{'CPU%':>8}{'MEM%':>8}"]
    for p in rows:
        cpu = NA if p.cpu_percent is None else f"{p.cpu_percent:.1f}"
        mem = NA if p.mem_percent is None else f"{p.mem_percent:.1f}"
        lines.append(f"  {p.pid:>7}  {p.name[:21]:<22}{cpu:>8}{mem:>8}")
    if not rows:
        lines.append(f"  {NA} (no process data)")
    return lines


def header(s: Snapshot, st: Style) -> list[str]:
    ts = datetime.datetime.fromtimestamp(s.timestamp).strftime("%Y-%m-%d %H:%M:%S")
    procs = NA if s.process_count is None else str(s.process_count)
    return [st.paint("syshealth", "1;36") + f"  {s.hostname}  {s.kernel}  {ts}",
            f"  uptime {human_duration(s.uptime_seconds)}   processes {procs}   sample window {s.interval:.1f}s"]


def section_alerts(active: list[dict], events: list[dict], st: Style) -> list[str]:
    lines = [_title("Alerts", st)]
    if not active:
        lines.append("  " + st.paint("none active", "32"))
    for a in active:
        tag = "CRIT" if a["severity"] == "critical" else "WARN"
        code = "1;31" if tag == "CRIT" else "33"
        lines.append(f"  {st.paint(tag, code)}  {a['metric']} [{a['target']}]  {a['value']:.1f} "
                     f"(threshold {a['threshold']:g})  since {a['since']}")
    for ev in events[-5:]:
        val = NA if ev["value"] is None else f"{ev['value']:.1f}"
        lines.append(st.paint(f"  event {ev['time']}  {ev['event']:<11} {ev['metric']} [{ev['target']}] {val}", "2"))
    return lines


SECTIONS = {
    "cpu": section_cpu, "memory": section_memory, "disk": section_disk,
    "network": section_network, "processes": section_processes,
}


def render(s: Snapshot, sections: list[str], color: bool = False, top_by: str = "cpu",
           thresholds: Optional[dict] = None, alerts: Optional[list[dict]] = None,
           events: Optional[list[dict]] = None) -> str:
    st = Style(color, thresholds)
    out = header(s, st)
    if alerts is not None:
        out += [""] + section_alerts(alerts, events or [], st)
    for name in sections:
        fn = SECTIONS[name]
        out.append("")
        out.extend(fn(s, st, top_by) if name == "processes" else fn(s, st))
    if s.unavailable:
        out += ["", st.paint("unavailable: " + ", ".join(s.unavailable), "2")]
    return "\n".join(out)


def render_findings(findings: list, color: bool = False, show_all: bool = False) -> str:
    """Findings keep observations, hypotheses and follow-up visibly separate."""
    st = Style(color)
    tags = {"critical": ("CRIT", "1;31"), "warning": ("WARN", "33"), "info": ("INFO", "36"),
            "ok": (" OK ", "32"), "unknown": ("UNKN", "2")}
    shown = [f for f in findings if show_all or f.status not in ("ok",)]
    out = [_title("Findings", st)]
    if not shown:
        out.append("  " + st.paint("no findings above 'ok'", "32"))
    for f in shown:
        tag, code = tags[f.status]
        out.append(f"  [{st.paint(tag, code)}] {f.id} - {f.summary}")
        if f.status == "ok" and not show_all:
            continue
        sections = (("Observed", f.observations, "- "),
                    ("Why it may matter", [f.why_it_matters] if f.why_it_matters else [], ""),
                    ("Possible explanations (unverified hypotheses)", f.hypotheses, "- "),
                    ("Follow-up (read-only, run by you)", f.follow_up, "$ "),
                    ("Limitations", f.limitations, "- "))
        for title, items, bullet in sections:
            if items:
                out.append(f"      {title}:")
                out += [f"        {bullet}{i.strip()}" if not i.startswith("  ") else f"        {i}" for i in items]
    return "\n".join(out)
