"""Optional Prometheus exporter (standard library only).

Design:
  * A background thread samples the host every ``refresh`` seconds and caches the rendered metrics, so a
    scrape never triggers collection work (scraping cannot load the host, however often it happens).
  * Binds to loopback by default. A non-loopback bind needs ``--allow-remote`` AND a bearer token file.
  * Labels are low-cardinality by construction: mountpoint, fstype, network device, alert metric/target/
    severity, load period. Never per-process (pid/name/command line); series counts are capped.
  * A metric that could not be read is omitted, never exported as 0.
"""

from __future__ import annotations

import hmac
import http.server
import ipaddress
import math
import os
import threading
import time
from collections.abc import Callable
from typing import Optional

from . import __version__
from .alerts import AlertEngine
from .collectors import Snapshot, collect
from .config import Config

DEFAULT_HOST, DEFAULT_PORT = "127.0.0.1", 9877
MAX_SERIES = 64          # cap on mountpoints / network devices exported
MAX_ALERT_SERIES = 100
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


class ExporterError(ValueError):
    pass


# ----------------------------------------------------------- exposition ------

def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt(value: float) -> str:
    return str(int(value)) if float(value).is_integer() and abs(value) < 1e15 else repr(float(value))


class _Exposition:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def add(self, name: str, kind: str, help_text: str, samples: list[tuple[dict[str, str], Optional[float]]]) -> None:
        good = [(lbl, v) for lbl, v in samples if v is not None and math.isfinite(v)]
        if not good:
            return                      # nothing readable: omit the family entirely
        self.lines += [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"]
        for labels, value in good:
            lab = ",".join(f'{k}="{_esc(str(v))}"' for k, v in labels.items())
            self.lines.append(f"{name}{{{lab}}} {_fmt(value)}" if lab else f"{name} {_fmt(value)}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def _ratio(pct: Optional[float]) -> Optional[float]:
    return None if pct is None else pct / 100.0


def render_metrics(snap: Snapshot, alerts: list[dict]) -> str:
    """Pure function: snapshot + active alerts -> Prometheus text exposition."""
    x = _Exposition()
    x.add("syshealth_build_info", "gauge", "Version of the syshealth exporter.", [({"version": __version__}, 1)])
    x.add("syshealth_cpu_utilization_ratio", "gauge",
          "Host CPU busy ratio (0-1) over the sampling window.", [({}, _ratio(snap.cpu_percent))])
    x.add("syshealth_cpu_count", "gauge", "Number of logical CPUs.", [({}, snap.cpu_count)])
    if snap.loadavg:
        x.add("syshealth_load_average", "gauge", "Load average.",
              [({"period": p}, v) for p, v in zip(("1m", "5m", "15m"), snap.loadavg, strict=True)])
    x.add("syshealth_uptime_seconds", "gauge", "Seconds since boot.", [({}, snap.uptime_seconds)])
    x.add("syshealth_processes", "gauge", "Number of processes.", [({}, snap.process_count)])

    m = snap.memory
    if m is not None:
        x.add("syshealth_memory_total_bytes", "gauge", "Total physical memory.", [({}, m.total)])
        x.add("syshealth_memory_available_bytes", "gauge", "Memory available without swapping (MemAvailable).",
              [({}, m.available)])
        x.add("syshealth_memory_utilization_ratio", "gauge", "(MemTotal - MemAvailable) / MemTotal.",
              [({}, _ratio(m.percent))])
        x.add("syshealth_swap_total_bytes", "gauge", "Total swap.", [({}, m.swap_total)])
        x.add("syshealth_swap_utilization_ratio", "gauge", "Swap used ratio (omitted when no swap).",
              [({}, _ratio(m.swap_percent))])

    if snap.disks is not None:
        disks = sorted(snap.disks, key=lambda d: d.mount)[:MAX_SERIES]
        def lab(d) -> dict[str, str]:
            return {"mountpoint": d.mount, "fstype": d.fstype}
        x.add("syshealth_filesystem_utilization_ratio", "gauge", "Filesystem used ratio, as df reports it.",
              [(lab(d), _ratio(d.percent)) for d in disks])
        x.add("syshealth_filesystem_size_bytes", "gauge", "Filesystem size.", [(lab(d), d.total) for d in disks])
        x.add("syshealth_filesystem_available_bytes", "gauge", "Filesystem space available to unprivileged users.",
              [(lab(d), d.free) for d in disks])

    if snap.network is not None:
        nics = sorted(snap.network, key=lambda i: i.name)[:MAX_SERIES]
        for name, attr, help_text in (
                ("syshealth_network_receive_bytes_total", "rx_bytes", "Bytes received."),
                ("syshealth_network_transmit_bytes_total", "tx_bytes", "Bytes transmitted."),
                ("syshealth_network_receive_errors_total", "rx_errors", "Receive errors."),
                ("syshealth_network_transmit_errors_total", "tx_errors", "Transmit errors."),
                ("syshealth_network_receive_drops_total", "rx_dropped", "Received packets dropped."),
                ("syshealth_network_transmit_drops_total", "tx_dropped", "Transmit packets dropped.")):
            x.add(name, "counter", help_text + " Counter since boot.",
                  [({"device": i.name}, getattr(i, attr)) for i in nics])

    counts = {s: sum(1 for a in alerts if a["severity"] == s) for s in ("warning", "critical")}
    x.add("syshealth_alerts_active", "gauge", "Number of currently active syshealth alerts.",
          [({"severity": s}, n) for s, n in counts.items()])      # a real count, so 0 is meaningful
    x.add("syshealth_alert_active", "gauge", "1 for each currently active alert.",
          [({"metric": a["metric"], "target": a["target"], "severity": a["severity"]}, 1)
           for a in alerts[:MAX_ALERT_SERIES]])
    x.add("syshealth_metric_unavailable", "gauge", "1 when a metric could not be read on the last collection.",
          [({"metric": n}, 1) for n in sorted(snap.unavailable)])
    return x.text()


# ------------------------------------------------------------ collector ------

class Collector:
    """Holds the latest rendered metrics plus collection-health counters (thread-safe)."""

    def __init__(self, cfg: Config, sample: float = 1.0, refresh: float = 15.0,
                 collect_fn: Callable[..., Snapshot] = collect, clock: Callable[[], float] = time.time):
        self.engine = AlertEngine(cfg)
        self.sample, self.refresh = sample, refresh
        self._collect, self._clock = collect_fn, clock
        self._lock = threading.Lock()
        self._body: Optional[str] = None
        self.errors = 0
        self.last_success: Optional[float] = None
        self.last_duration: Optional[float] = None

    def run_once(self) -> bool:
        started = time.monotonic()
        try:
            snap = self._collect(self.sample, 5)
            self.engine.evaluate(snap)
            body = render_metrics(snap, self.engine.active)
        except Exception:  # noqa: BLE001 - a failed cycle must never kill the exporter
            with self._lock:
                self.errors += 1
            return False
        with self._lock:
            self._body, self.last_success = body, self._clock()
            self.last_duration = time.monotonic() - started
        return True

    def scrape(self) -> tuple[int, str]:
        with self._lock:
            if self._body is None:
                return 503, "no successful collection yet\n"
            meta = _Exposition()
            meta.add("syshealth_collection_errors_total", "counter",
                     "Collection cycles that raised an error.", [({}, self.errors)])
            meta.add("syshealth_last_collection_timestamp_seconds", "gauge",
                     "Unix time of the last successful collection.", [({}, self.last_success)])
            meta.add("syshealth_collection_duration_seconds", "gauge",
                     "Duration of the last successful collection.", [({}, self.last_duration)])
            return 200, self._body + meta.text()

    def healthy(self) -> bool:
        with self._lock:
            return self.last_success is not None and self._clock() - self.last_success < 3 * self.refresh + self.sample


class SamplerThread(threading.Thread):
    def __init__(self, collector: Collector):
        super().__init__(name="syshealth-sampler", daemon=True)
        self.collector, self.stop_event = collector, threading.Event()

    def run(self) -> None:
        wait = max(0.1, self.collector.refresh - self.collector.sample)
        while not self.stop_event.wait(wait):
            self.collector.run_once()

    def stop(self) -> None:
        self.stop_event.set()
        self.join(timeout=self.collector.sample + 5)


# --------------------------------------------------------------- server ------

def make_server(host: str, port: int, collector: Collector,
                token: Optional[str] = None) -> http.server.ThreadingHTTPServer:
    expected = f"Bearer {token}" if token else None

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "syshealth-exporter"
        sys_version = ""
        timeout = 5                       # drop slow/idle clients instead of holding a thread

        def _send(self, code: int, text: str, ctype: str = "text/plain; charset=utf-8", extra=None) -> None:
            body = text.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if expected is None:
                return True
            given = self.headers.get("Authorization", "")
            return hmac.compare_digest(given.encode(), expected.encode())     # constant-time

        def do_GET(self) -> None:  # noqa: N802
            if not self._authorized():
                return self._send(401, "unauthorized\n", extra={"WWW-Authenticate": 'Bearer realm="syshealth"'})
            path = self.path.split("?", 1)[0]
            if path == "/metrics":
                code, text = collector.scrape()
                return self._send(code, text, CONTENT_TYPE if code == 200 else "text/plain; charset=utf-8")
            if path == "/healthz":
                ok = collector.healthy()
                return self._send(200 if ok else 503, "ok\n" if ok else "stale or no data\n")
            self._send(404, "not found\n")

        def _not_allowed(self) -> None:
            self._send(405, "method not allowed\n", extra={"Allow": "GET"})

        do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _not_allowed  # noqa: N815

        def log_message(self, fmt: str, *args) -> None:       # quiet; problems surface as status codes
            pass

    srv = http.server.ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv


# ------------------------------------------------------- validation / run ----

def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False            # unknown hostname: treat as non-loopback


def read_token(path: str) -> tuple[str, Optional[str]]:
    """Return (token, warning). The token comes from a file so it never appears in the process list."""
    try:
        with open(path, encoding="utf-8") as fh:
            token = fh.read().strip()
        mode = os.stat(path).st_mode & 0o777
    except OSError as e:
        raise ExporterError(f"cannot read token file {path}: {e.strerror or e}") from e
    if not token:
        raise ExporterError(f"token file {path} is empty")
    if any(c.isspace() for c in token) or not token.isprintable():
        raise ExporterError("token must be a single printable string without whitespace")
    warn = f"token file {path} is readable by other users (mode {mode:o}); chmod 600 it" if mode & 0o077 else None
    return token, warn


def validate_bind(host: str, port: int, allow_remote: bool,
                  token_file: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Return (token, warning) or raise ExporterError. Enforces the loopback-by-default policy."""
    if not 1 <= port <= 65535:
        raise ExporterError(f"port must be 1-65535, got {port}")
    token = warn = None
    if token_file:
        token, warn = read_token(token_file)
    if not is_loopback(host):
        if not allow_remote:
            raise ExporterError(f"refusing to bind to non-loopback address {host!r}; pass --allow-remote "
                                "and --token-file (and restrict access with a firewall)")
        if token is None:
            raise ExporterError("--allow-remote requires --token-file so the endpoint is not served unauthenticated")
    return token, warn


def run(host: str, port: int, cfg: Config, sample: float, refresh: float, allow_remote: bool = False,
        token_file: Optional[str] = None, err=None) -> int:
    """Serve until SIGINT/SIGTERM. Returns a process exit code."""
    import signal
    import sys
    err = err or sys.stderr
    try:
        token, warning = validate_bind(host, port, allow_remote, token_file)
    except ExporterError as e:
        print(f"syshealth: exporter error: {e}", file=err)
        return 2
    if warning:
        print(f"syshealth: warning: {warning}", file=err)
    if refresh < sample:
        print("syshealth: exporter error: --refresh must be >= --sample", file=err)
        return 2

    collector = Collector(cfg, sample, refresh)
    if not collector.run_once():
        print("syshealth: warning: first collection failed; /metrics returns 503 until one succeeds", file=err)
    try:
        server = make_server(host, port, collector, token)
    except OSError as e:
        print(f"syshealth: exporter error: cannot listen on {host}:{port}: {e.strerror or e}", file=err)
        return 2
    sampler = SamplerThread(collector)
    sampler.start()

    def _stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()   # shutdown() must run off the serving thread
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _stop)
    shown = f"[{host}]" if ":" in host else host
    print(f"syshealth exporter listening on http://{shown}:{server.server_address[1]}/metrics"
          f"{' (bearer token required)' if token else ''}; Ctrl+C to stop", file=err, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        sampler.stop()
        server.server_close()
    print("syshealth exporter stopped", file=err)
    return 0
