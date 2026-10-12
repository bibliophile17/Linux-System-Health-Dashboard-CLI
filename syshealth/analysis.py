"""Deterministic incident analysis: correlate existing diagnostic findings into ranked *possible* causes.

This module adds NO new thresholds or measurements. It consumes the `Finding`s produced by `diagnostics.py`
(plus the raw evidence for corroboration) and answers three questions the individual checks cannot:
  * which explanation is best supported when several checks fire, and which findings are merely consequences;
  * how strong is the evidence (a label, NOT a probability), counting corroboration and contradiction;
  * when should the tool decline to name a cause (conflicting, weak or missing evidence).

Rules of the road: causes are hypotheses; every supporting statement is a verbatim observation from a finding;
nothing is executed; weak or conflicting evidence yields `inconclusive`, and missing metrics yield
`insufficient_data`, never a guess.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

from .config import Config
from .diagnostics import (
    CLOSE_WAIT_WARN,
    DOMINANT_MEMORY_SHARE,
    DOMINANT_PROCESS_SHARE,
    IO_UTIL_CRIT,
    IO_UTIL_WARN,
    PSI_WARN,
    SYN_RECV_WARN,
    TIME_WAIT_WARN,
    Finding,
)
from .evidence import Evidence

METHOD = "rule-based/v1 (deterministic)"
DISCLAIMER = ("Causes are ranked hypotheses derived from evidence strength, not established root causes. "
              "Confidence is an evidence-strength label, not a probability. No commands are executed.")
STRONG_AT, MODERATE_AT = 5, 3
CONF_RANK = {"weak": 1, "moderate": 2, "strong": 3}
PSI_QUIET = 1.0     # below this (percent of time stalled) a pressure counter is treated as "no stall observed"

CAUSE_TITLES = {
    "cpu_saturation": "CPU saturation",
    "memory_pressure": "Memory pressure",
    "disk_space_exhaustion": "Filesystem space exhaustion",
    "disk_io_saturation": "Disk I/O saturation",
    "network_interface_errors": "Network interface errors/drops",
    "service_failure": "Service/process failure",
    "connection_state_buildup": "TCP connection-state build-up",
    "process_proliferation": "Process proliferation",
    "unexplained_load": "High load with no resource explanation",
}
# Deterministic tie-break order, and the finding that is the entry point for each cause.
PRIORITY = list(CAUSE_TITLES)
FINDING_FOR = {"cpu_saturation": "cpu", "memory_pressure": "memory", "disk_space_exhaustion": "disk_space",
               "disk_io_saturation": "disk_io", "network_interface_errors": "network_errors",
               "service_failure": "services", "connection_state_buildup": "sockets",
               "process_proliferation": "process_count"}
# Causes whose underlying reason cannot be established from host counters never exceed this confidence.
CAP = {"network_interface_errors": "moderate", "service_failure": "moderate", "connection_state_buildup": "moderate",
       "process_proliferation": "moderate", "unexplained_load": "weak"}
CAVEATS = {
    "cpu_saturation": "What made the CPU busy (release, input, loop) is not observable; figures are window averages.",
    "memory_pressure": "A leak versus a legitimately large working set cannot be distinguished from one snapshot.",
    "disk_space_exhaustion": "Which directory is growing, and how fast, has not been measured; inodes and "
                             "deleted-but-open files are not checked.",
    "disk_io_saturation": "The process generating the I/O is not identified.",
    "network_interface_errors": "Cable, driver, switch-port or buffer origin cannot be told from counters alone.",
    "service_failure": "The exit code, signal and reason for the failure are not captured.",
    "connection_state_buildup": "Sockets are not attributed to a process.",
    "process_proliferation": "Zombies versus real workers cannot be told apart from the process count.",
    "unexplained_load": "Blocked tasks, lock contention and cgroup throttling are not observable by these checks "
                        "(the load figure alone does not say what the tasks are waiting for).",
}
EXTRA_STEPS = {
    "unexplained_load": ["ps -eo pid,stat,wchan:20,comm | awk '$2 ~ /D/'", "cat /proc/pressure/cpu",
                         "cat /sys/fs/cgroup/cpu.stat", "vmstat 1 5"],
    "memory_pressure": ["cat /proc/pressure/memory", "vmstat 1 5"],
    "cpu_saturation": ["cat /proc/pressure/cpu"],
    "connection_state_buildup": ["ss -s"],
}


@dataclass
class RankedCause:
    cause: str
    title: str
    confidence: str                         # weak | moderate | strong (evidence strength, not probability)
    points: int
    supporting: list[str] = field(default_factory=list)       # verbatim observations from findings
    contradicting: list[str] = field(default_factory=list)    # "<observation> -- <what it implies>"
    missing_evidence: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)       # read-only commands for a human; never executed
    consequence_of: Optional[str] = None
    is_hypothesis: bool = True


@dataclass
class Analysis:
    status: str            # healthy | diagnosed | multiple_issues | inconclusive | insufficient_data
    headline: str
    causes: list[RankedCause]
    observations: list[str]
    uncertainties: list[str]
    not_assessed: list[str]
    method: str = METHOD
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------------ helpers --

class _Tally:
    def __init__(self) -> None:
        self.points = 0
        self.supporting: list[str] = []
        self.contradicting: list[str] = []
        self.missing: list[str] = []

    def support(self, pts: int, obs: Optional[str]) -> None:
        if obs is None:          # no citable observation -> the signal is not counted
            return
        self.points += pts
        if obs not in self.supporting:
            self.supporting.append(obs)

    def contradict(self, pts: int, obs: Optional[str], implication: str) -> None:
        if obs is None:
            return
        self.points -= pts
        self.contradicting.append(f"{obs} -- {implication}")


def _obs(f: Optional[Finding], prefix: str) -> Optional[str]:
    if f is None:
        return None
    return next((o for o in f.observations if o.startswith(prefix)), None)


def _active(f: Optional[Finding]) -> bool:
    return f is not None and f.status in ("warning", "critical")


def _load_per_core(ev: Evidence) -> Optional[float]:
    s = ev.snap
    return s.loadavg[0] / s.cpu_count if s.loadavg and s.cpu_count else None


def _psi(ev: Evidence, res: str) -> Optional[float]:
    p = (ev.pressure or {}).get(res)
    return None if p is None else p.some_avg10


def _confidence(t: _Tally, cause: str) -> str:
    if t.points >= STRONG_AT and not t.contradicting:
        conf = "strong"
    elif t.points >= MODERATE_AT:
        conf = "moderate"          # includes strong-by-points evidence that is contradicted
    else:
        conf = "weak"
    cap = CAP.get(cause)
    return min(conf, cap, key=CONF_RANK.__getitem__) if cap else conf


# -------------------------------------------------------------- cause rules --

def _cpu(F, ev, cfg) -> Optional[RankedCause]:
    f, s = F.get("cpu"), ev.snap
    w, c = cfg.thresholds["cpu_percent"]
    if not _active(f) or s.cpu_percent is None or s.cpu_percent < w:
        return None                                  # load-only findings are handled by `unexplained_load`
    t = _Tally()
    t.support(3 if s.cpu_percent >= c else 2, _obs(f, "CPU busy"))
    psi, lpc = _psi(ev, "cpu"), _load_per_core(ev)
    if psi is not None and psi >= PSI_WARN:
        t.support(2, _obs(f, "cpu pressure"))
    elif psi is not None and psi < PSI_QUIET:
        t.contradict(1, _obs(f, "cpu pressure"), "no task is stalled waiting for CPU, so this may be a short burst")
    if lpc is not None and lpc >= cfg.thresholds["load_per_core"][0]:
        t.support(1, _obs(f, "1-min load average"))
    elif lpc is not None and lpc < 0.5:
        t.contradict(1, _obs(f, "1-min load average"), "load average is low, so busy time may not be sustained")
    top = s.top_cpu[0] if s.top_cpu else None
    if top and top.cpu_percent is not None and s.cpu_percent > 0 and s.cpu_count:
        if top.cpu_percent / (s.cpu_percent * s.cpu_count) >= DOMINANT_PROCESS_SHARE:
            t.support(1, _obs(f, "top CPU process"))
    return _make("cpu_saturation", t, F)


def _memory(F, ev, cfg) -> Optional[RankedCause]:
    f, m = F.get("memory"), ev.snap.memory
    if not _active(f) or m is None:
        return None
    w, c = cfg.thresholds["memory_percent"]
    sw = cfg.thresholds["swap_percent"][0]
    ram_high = m.percent is not None and m.percent >= w
    psi = _psi(ev, "memory")
    psi_high = psi is not None and psi >= PSI_WARN
    swap_high = m.swap_percent is not None and m.swap_percent >= sw
    if not (ram_high or psi_high or swap_high):
        return None
    t = _Tally()
    if ram_high:
        t.support(3 if m.percent >= c else 2, _obs(f, "RAM used"))
    if swap_high:
        t.support(1, _obs(f, "swap used"))
    if psi_high:
        t.support(2, _obs(f, "memory pressure"))
    elif psi is not None and psi < PSI_QUIET and ram_high:
        t.contradict(1, _obs(f, "memory pressure"),
                     "no task is stalled on memory, so usage may be cache or working set")
    if (ev.oom_kills or 0) > 0 and (ram_high or psi_high):
        t.support(1, _obs(f, "OOM-killer"))
        if ev.failed_units:
            t.support(1, _obs(F.get("services"), "failed systemd units"))
    if ram_high and not swap_high and not psi_high and not (ev.oom_kills or 0):
        t.contradict(1, _obs(f, "RAM used"),
                     "high usage without swap activity, stalls or OOM kills does not show starvation")
    if ev.snap.top_mem and ev.snap.top_mem[0].mem_percent and ev.snap.top_mem[0].mem_percent >= DOMINANT_MEMORY_SHARE:
        t.support(1, _obs(f, "top memory process"))
    return _make("memory_pressure", t, F)


def _disk_space(F, ev, cfg) -> Optional[RankedCause]:
    f = F.get("disk_space")
    if not _active(f):
        return None
    t = _Tally()
    t.points = 5 if f.status == "critical" else 3        # a direct measurement of the thing in question
    t.supporting = [o for o in f.observations if "% used" in o]
    return _make("disk_space_exhaustion", t, F)


def _disk_io(F, ev, cfg) -> Optional[RankedCause]:
    f = F.get("disk_io")
    if not _active(f) or not ev.diskio:
        return None
    t = _Tally()
    top = max(ev.diskio, key=lambda r: r.util_percent)
    if top.util_percent >= IO_UTIL_WARN:
        busy_obs = next((o for o in f.observations if "% busy" in o), None)
        t.support(3 if top.util_percent >= IO_UTIL_CRIT else 2, busy_obs)
    psi = _psi(ev, "io")
    if psi is not None and psi >= PSI_WARN:
        t.support(2, _obs(f, "io pressure"))
    lpc, cpu = _load_per_core(ev), ev.snap.cpu_percent
    if lpc is not None and cpu is not None and lpc >= cfg.thresholds["load_per_core"][0] \
            and cpu < cfg.thresholds["cpu_percent"][0]:
        cf = F.get("cpu")
        t.support(1, _obs(cf, "CPU busy"))
        t.support(0, _obs(cf, "1-min load average"))
        t.missing.append("Load is high while CPU is low, which fits tasks waiting on I/O (not proven).")
    if t.points <= 0:
        return None
    return _make("disk_io_saturation", t, F)


def _network(F, ev, cfg) -> Optional[RankedCause]:
    f = F.get("network_errors")
    if not _active(f):
        return None                       # 'info' (historic counters only) is deliberately not a cause
    t = _Tally()
    t.points = 3
    t.supporting = [o for o in f.observations if "during the" in o]
    if any(v["errors"] > 0 for v in (ev.net_deltas or {}).values()):
        t.points += 1
    return _make("network_interface_errors", t, F)


def _service(F, ev, cfg) -> Optional[RankedCause]:
    f = F.get("services")
    if not _active(f):
        return None
    t = _Tally()
    t.support(3, _obs(f, "failed systemd units"))
    if (ev.oom_kills or 0) > 0:
        t.support(1, _obs(f, "OOM-killer"))
        t.missing.append("The OOM counter is cumulative and untimestamped: "
                         "a link to these failures is not established.")
    return _make("service_failure", t, F)


def _sockets(F, ev, cfg) -> Optional[RankedCause]:
    f = F.get("sockets")
    if not _active(f) or ev.sockets is None:
        return None
    st = ev.sockets.states
    t = _Tally()
    obs = _obs(f, "connection states")
    if st.get("CLOSE_WAIT", 0) >= CLOSE_WAIT_WARN:
        t.support(3, obs)
    if st.get("SYN_RECV", 0) >= SYN_RECV_WARN:
        t.support(3, obs)
    if st.get("TIME_WAIT", 0) >= TIME_WAIT_WARN:
        t.support(1, obs)         # TIME_WAIT alone is common and usually harmless: weak by itself
    if t.points <= 0:
        return None
    return _make("connection_state_buildup", t, F)


def _procs(F, ev, cfg) -> Optional[RankedCause]:
    f = F.get("process_count")
    if not _active(f):
        return None
    t = _Tally()
    t.support(3 if f.status == "critical" else 2, f.observations[0] if f.observations else None)
    return _make("process_proliferation", t, F)


def _unexplained(F, ev, cfg, found: dict[str, RankedCause]) -> Optional[RankedCause]:
    lpc, cpu = _load_per_core(ev), ev.snap.cpu_percent
    load_warn, cpu_warn = cfg.thresholds["load_per_core"][0], cfg.thresholds["cpu_percent"][0]
    if lpc is None or cpu is None or lpc < load_warn or cpu >= cpu_warn:
        return None
    if {"disk_io_saturation", "memory_pressure", "cpu_saturation"} & set(found):
        return None
    if any(p.some_avg10 >= PSI_WARN for p in (ev.pressure or {}).values()):
        return None
    cf = F.get("cpu")
    t = _Tally()
    t.support(1, _obs(cf, "1-min load average"))
    t.contradict(0, _obs(cf, "CPU busy"), "CPU is not busy, so the load is not CPU-bound")
    t.missing.append("No CPU, memory or I/O stall pressure was observed to explain the load.")
    return _make("unexplained_load", t, F)


def _make(cause: str, t: _Tally, F) -> Optional[RankedCause]:
    if not t.supporting:
        return None
    f = F.get(FINDING_FOR.get(cause, ""))
    steps = list(f.follow_up) if f else []
    for step in EXTRA_STEPS.get(cause, []):
        if step not in steps:
            steps.append(step)
    return RankedCause(cause, CAUSE_TITLES[cause], _confidence(t, cause), t.points, t.supporting,
                       t.contradicting, t.missing, steps[:6])


# ------------------------------------------------------------------ analyze --

def analyze(findings: list[Finding], ev: Evidence, cfg: Config) -> Analysis:
    F = {f.id: f for f in findings}
    unknown = sorted(f.id for f in findings if f.status == "unknown")
    not_assessed = [f"{i}: {F[i].summary}" for i in unknown]

    found: dict[str, RankedCause] = {}
    for rule in (_cpu, _memory, _disk_space, _disk_io, _network, _service, _sockets, _procs):
        c = rule(F, ev, cfg)
        if c is not None:
            found[c.cause] = c
    u = _unexplained(F, ev, cfg, found)
    if u is not None:
        found[u.cause] = u

    # Root cause before consequence: OOM kills plus a failed service suggest the service died *because of* memory.
    mem, svc = found.get("memory_pressure"), found.get("service_failure")
    if mem and svc and (ev.oom_kills or 0) > 0 and CONF_RANK[mem.confidence] >= CONF_RANK["moderate"]:
        svc.consequence_of = "memory_pressure"

    causes = sorted(found.values(), key=lambda c: (-c.points, PRIORITY.index(c.cause)))
    roots = [c for c in causes if c.consequence_of is None]
    causes = roots + [c for c in causes if c.consequence_of is not None]

    asserted = [c for c in causes if CONF_RANK[c.confidence] >= CONF_RANK["moderate"]]
    independent = [c for c in asserted if c.consequence_of is None]
    cpu_unknown, mem_unknown = "cpu" in unknown, "memory" in unknown
    if not causes:
        status = "insufficient_data" if (cpu_unknown and mem_unknown) or len(unknown) >= 4 else "healthy"
    elif not asserted:
        status = "inconclusive"
    else:
        status = "multiple_issues" if len(independent) >= 2 else "diagnosed"

    observations: list[str] = []
    for c in causes:
        for o in c.supporting:
            if o not in observations:
                observations.append(o)

    return Analysis(status, _headline(status, causes), causes, observations,
                    _uncertainties(status, causes, not_assessed, ev), not_assessed)


def _headline(status: str, causes: list[RankedCause]) -> str:
    if status == "healthy":
        return "No problems detected in the checks that could run."
    if status == "insufficient_data":
        return "Insufficient data: key metrics could not be read, so no diagnosis is offered."
    label = ", ".join(f"{c.title} ({c.confidence})" for c in causes[:3])
    if status == "inconclusive":
        return f"Inconclusive: the evidence is weak or conflicting. Weakest hypotheses only: {label}."
    if status == "multiple_issues":
        return f"Multiple independent issues are indicated: {label}."
    return f"Best-supported explanation: {causes[0].title} ({causes[0].confidence} evidence)."


def _uncertainties(status: str, causes: list[RankedCause], not_assessed: list[str], ev: Evidence) -> list[str]:
    out = [f"Based on a single ~{ev.snap.interval:.0f}s sampling window; intermittent problems can be missed."]
    out += [f"Not assessed: {n}" for n in not_assessed]
    if status == "insufficient_data":
        out.append("No diagnosis is possible until the unreadable metrics are available.")
    for c in causes:
        out.append(f"{c.title}: {CAVEATS[c.cause]}")
        out += [f"{c.title}: {m}" for m in c.missing_evidence]
        if CONF_RANK[c.confidence] == CONF_RANK["weak"]:
            out.append(f"{c.title}: the evidence is weak; this is a hypothesis to check, not a finding.")
        if c.cause == "memory_pressure" and c.contradicting:
            out.append("Memory: high usage alone does not show contention; pressure, swap and OOM evidence "
                       "do not support starvation.")
        if c.cause == "connection_state_buildup" and CONF_RANK[c.confidence] == 1:
            out.append("Sockets: TIME_WAIT alone is common TCP behaviour and usually harmless.")
        if c.consequence_of:
            out.append(f"{c.title} is treated as a consequence of {CAUSE_TITLES[c.consequence_of]}; this is inferred "
                       "from co-occurrence, not proven.")
    return out


# --------------------------------------------------------------- rendering ---

def render_analysis(a: Analysis) -> str:
    out = [f"== Incident analysis ({a.method}) ==", f"  status: {a.status}", f"  {a.headline}"]
    for i, c in enumerate(a.causes, 1):
        tag = f" (consequence of {CAUSE_TITLES[c.consequence_of]})" if c.consequence_of else ""
        out.append(f"  {i}. {c.title} - {c.confidence} evidence, {c.points} pts{tag}   [HYPOTHESIS]")
        for label, items, prefix in (("Supporting observations", c.supporting, "- "),
                                     ("Contradicting evidence", c.contradicting, "- "),
                                     ("Missing evidence", c.missing_evidence, "- "),
                                     ("Next steps (read-only, run by you)", c.next_steps, "$ ")):
            if items:
                out.append(f"       {label}:")
                out += [f"         {prefix}{x}" for x in items]
    out.append("  Uncertainties:")
    out += [f"    - {u}" for u in a.uncertainties]
    out.append(f"  {a.disclaimer}")
    return "\n".join(out)
