import os
import re
import threading
import time
import urllib.error
import urllib.request

import pytest
from helpers import make_snap

from syshealth import exporter as ex
from syshealth.alerts import AlertEngine
from syshealth.collectors import DiskUsage, NetIface
from syshealth.config import Config

SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})? (\S+)$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse_exposition(text):
    """Strict-ish parser of the Prometheus text format; fails the test on anything malformed."""
    types, helps, samples = {}, {}, []
    assert text.endswith("\n")
    for line in text.splitlines():
        if line.startswith("# HELP "):
            name, _, rest = line[7:].partition(" ")
            assert rest and name not in helps, line
            helps[name] = rest
        elif line.startswith("# TYPE "):
            name, _, kind = line[7:].partition(" ")
            assert kind in ("gauge", "counter", "histogram", "summary", "untyped") and name not in types, line
            types[name] = kind
        else:
            m = SAMPLE.match(line)
            assert m, f"malformed sample line: {line!r}"
            name, _, labels, value = m.groups()
            assert name in types, f"sample before TYPE: {line!r}"
            float(value)                                     # must parse
            assert "nan" not in value.lower() and "inf" not in value.lower()
            lbls = dict(LABEL.findall(labels or ""))
            if labels:
                assert re.sub(r'[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*",?', "", labels) == "", line
            samples.append((name, lbls, float(value)))
    for name, kind in types.items():
        assert name in helps
        if kind == "counter":
            assert name.endswith("_total"), name
    return types, samples


def rich_snap(**kw):
    s = make_snap(cpu=42.0, mem=60.0, swap=10.0, disks={"/": 30, "/data": 95}, procs=123, **kw)
    s.network = [NetIface("eth0", 100, 1, 2, 3, 200, 4, 5, 6), NetIface("lo", 1, 1, 0, 0, 1, 1, 0, 0)]
    return s


def render(snap=None, cfg=None):
    snap = snap or rich_snap()
    eng = AlertEngine(cfg or Config())
    eng.evaluate(snap)
    return ex.render_metrics(snap, eng.active)


# ---- exposition format ------------------------------------------------------
def test_output_is_valid_exposition_with_expected_values():
    types, samples = parse_exposition(render())
    by = {(n, tuple(sorted(lb.items()))): v for n, lb, v in samples}
    assert by[("syshealth_cpu_utilization_ratio", ())] == pytest.approx(0.42)
    assert by[("syshealth_memory_utilization_ratio", ())] == pytest.approx(0.6)
    assert by[("syshealth_swap_utilization_ratio", ())] == pytest.approx(0.1)
    assert by[("syshealth_filesystem_utilization_ratio", (("fstype", "ext4"), ("mountpoint", "/data")))] == pytest.approx(0.95)
    assert by[("syshealth_network_receive_errors_total", (("device", "eth0"),))] == 2
    assert by[("syshealth_processes", ())] == 123
    assert by[("syshealth_load_average", (("period", "1m"),))] == pytest.approx(0.1)
    assert types["syshealth_network_receive_bytes_total"] == "counter" and types["syshealth_cpu_utilization_ratio"] == "gauge"


def test_alert_metrics_reflect_active_alerts():
    _, samples = parse_exposition(render())
    counts = {lb["severity"]: v for n, lb, v in samples if n == "syshealth_alerts_active"}
    assert counts == {"warning": 0, "critical": 1}                     # /data at 95% >= crit 90
    active = [lb for n, lb, v in samples if n == "syshealth_alert_active"]
    assert active == [{"metric": "disk_percent", "target": "/data", "severity": "critical"}]


def test_healthy_host_reports_zero_alert_counts_explicitly():
    _, samples = parse_exposition(render(make_snap()))
    assert {lb["severity"]: v for n, lb, v in samples if n == "syshealth_alerts_active"} == {"warning": 0, "critical": 0}
    assert not [1 for n, *_ in samples if n == "syshealth_alert_active"]


def test_unreadable_metrics_are_omitted_not_zero():
    snap = make_snap(cpu=None, mem=None, procs=None, load1=None, disks="unreadable")
    snap.unavailable += ["cpu_percent", "memory"]
    snap.network = None
    snap.uptime_seconds = None
    snap.cpu_count = None
    types, samples = parse_exposition(ex.render_metrics(snap, []))
    names = {n for n, *_ in samples}
    assert not names & {"syshealth_cpu_utilization_ratio", "syshealth_memory_utilization_ratio", "syshealth_processes",
                        "syshealth_load_average", "syshealth_filesystem_utilization_ratio", "syshealth_uptime_seconds",
                        "syshealth_network_receive_bytes_total", "syshealth_cpu_count"}
    flagged = {lb["metric"] for n, lb, v in samples if n == "syshealth_metric_unavailable"}
    assert flagged == set(snap.unavailable) and {"cpu_percent", "memory"} <= flagged
    assert all(n in types for n in names)


def test_swap_ratio_omitted_when_no_swap_but_total_reported_as_zero():
    _, samples = parse_exposition(render(make_snap(swap=None)))
    names = {n: v for n, lb, v in samples}
    assert "syshealth_swap_utilization_ratio" not in names and names["syshealth_swap_total_bytes"] == 0


def test_label_values_are_escaped():
    snap = make_snap()
    snap.disks = [DiskUsage('/mnt/we"ird\\path\nx', "ext4", 100, 10, 90, 10.0)]
    text = ex.render_metrics(snap, [])
    assert '\\"' in text and "\\\\" in text and "\\n" in text
    _, samples = parse_exposition(text)                                 # still parseable
    assert any(lb.get("mountpoint") == 'we\\"ird'.replace('we', '/mnt/we') + '\\\\path\\nx' for n, lb, v in samples)


def test_no_high_cardinality_labels_and_series_are_capped():
    snap = make_snap()
    snap.disks = [DiskUsage(f"/m{i:03d}", "ext4", 100, 10, 90, 10.0) for i in range(500)]
    snap.network = [NetIface(f"veth{i:03d}", 0, 0, 0, 0, 0, 0, 0, 0) for i in range(500)]
    from helpers import everything_bad
    snap.top_cpu = everything_bad().snap.top_cpu                         # per-process data exists but must never leak
    _, samples = parse_exposition(ex.render_metrics(snap, []))
    assert sum(1 for n, *_ in samples if n == "syshealth_filesystem_utilization_ratio") == ex.MAX_SERIES
    assert sum(1 for n, *_ in samples if n == "syshealth_network_receive_bytes_total") == ex.MAX_SERIES
    labels = {k for _, lb, _ in samples for k in lb}
    assert labels <= {"version", "period", "mountpoint", "fstype", "device", "severity", "metric", "target"}
    assert not [n for n, *_ in samples if "process" in n and n != "syshealth_processes"]


def test_alert_series_are_capped():
    alerts = [{"metric": "disk_percent", "target": f"/m{i}", "severity": "warning"} for i in range(300)]
    _, samples = parse_exposition(ex.render_metrics(make_snap(), alerts))
    assert sum(1 for n, *_ in samples if n == "syshealth_alert_active") == ex.MAX_ALERT_SERIES


def test_rendering_is_deterministic():
    assert render() == render()


# ---- collector --------------------------------------------------------------
def make_collector(fn, **kw):
    return ex.Collector(Config(), sample=0.0, refresh=10.0, collect_fn=fn, **kw)


def test_scrape_before_first_collection_is_503():
    code, text = make_collector(lambda *a: rich_snap()).scrape()
    assert code == 503 and "no successful collection" in text


def test_scrape_appends_collection_health_metrics():
    clock = iter([1000.0] * 5)
    c = make_collector(lambda *a: rich_snap(), clock=lambda: next(clock))
    assert c.run_once() is True
    code, text = c.scrape()
    _, samples = parse_exposition(text)
    d = {n: v for n, lb, v in samples if not lb}
    assert code == 200 and d["syshealth_collection_errors_total"] == 0
    assert d["syshealth_last_collection_timestamp_seconds"] == 1000.0 and d["syshealth_collection_duration_seconds"] >= 0


def test_failed_collection_counts_error_and_keeps_last_good_data():
    calls = {"n": 0}

    def flaky(*a):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("boom")
        return rich_snap()
    c = make_collector(flaky)
    assert c.run_once() and not c.run_once() and c.run_once() is True
    _, text = c.scrape()
    assert "syshealth_collection_errors_total 1" in text


def test_first_collection_failure_then_recovery():
    state = {"fail": True}

    def fn(*a):
        if state["fail"]:
            raise RuntimeError("no /proc")
        return rich_snap()
    c = make_collector(fn)
    assert not c.run_once() and c.scrape()[0] == 503 and c.errors == 1
    state["fail"] = False
    assert c.run_once() and c.scrape()[0] == 200 and "syshealth_collection_errors_total 1" in c.scrape()[1]


def test_alert_engine_persists_across_collections():
    snaps = iter([rich_snap(), rich_snap()])
    c = make_collector(lambda *a: next(snaps))
    c.run_once()
    c.run_once()
    assert len(c.engine.active) == 1                                    # no duplicate alert after 2 cycles


def test_health_goes_stale():
    now = {"t": 1000.0}
    c = ex.Collector(Config(), sample=1.0, refresh=10.0, collect_fn=lambda *a: rich_snap(), clock=lambda: now["t"])
    assert c.healthy() is False
    c.run_once()
    assert c.healthy() is True
    now["t"] += 3 * 10.0 + 1.0 - 0.01
    assert c.healthy() is True
    now["t"] += 0.1
    assert c.healthy() is False


# ---- HTTP server ------------------------------------------------------------
class Served:
    def __init__(self, token=None, collector=None):
        self.collector = collector or make_collector(lambda *a: rich_snap())
        self.collector.run_once()
        self.server = ex.make_server("127.0.0.1", 0, self.collector, token)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def get(self, path, headers=None, method="GET"):
        req = urllib.request.Request(self.base + path, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode(), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), e.headers

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


@pytest.fixture
def served():
    s = Served()
    yield s
    s.close()


def test_server_binds_loopback_and_serves_metrics(served):
    assert served.server.server_address[0] == "127.0.0.1"
    code, body, headers = served.get("/metrics")
    assert code == 200 and headers["Content-Type"] == ex.CONTENT_TYPE
    parse_exposition(body)
    assert served.get("/metrics?x=1")[0] == 200                         # query string ignored


def test_unknown_paths_and_methods(served):
    assert served.get("/")[0] == 404 and served.get("/metrics/extra")[0] == 404
    for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD"):
        code, _, headers = served.get("/metrics", method=method)
        assert code == 405 and headers["Allow"] == "GET"


def test_healthz_reflects_collector_state():
    cold = Served(collector=make_collector(lambda *a: (_ for _ in ()).throw(RuntimeError("x"))))
    try:
        assert cold.get("/healthz")[0] == 503 and cold.get("/metrics")[0] == 503
    finally:
        cold.close()
    warm = Served()
    try:
        assert warm.get("/healthz")[0] == 200
    finally:
        warm.close()


def test_server_does_not_leak_python_version(served):
    _, _, headers = served.get("/metrics")
    assert "Python" not in headers["Server"] and "BaseHTTP" not in headers["Server"]


def test_bearer_token_enforced():
    s = Served(token="s3cret-token")
    try:
        assert s.get("/metrics")[0] == 401
        code, _, h = s.get("/metrics")
        assert h["WWW-Authenticate"].startswith("Bearer")
        assert s.get("/metrics", {"Authorization": "Bearer wrong"})[0] == 401
        assert s.get("/metrics", {"Authorization": "s3cret-token"})[0] == 401          # scheme required
        assert s.get("/healthz")[0] == 401                                              # every path is protected
        assert s.get("/metrics", {"Authorization": "Bearer s3cret-token"})[0] == 200
        assert s.get("/nope", {"Authorization": "Bearer s3cret-token"})[0] == 404
    finally:
        s.close()


def test_unauthenticated_response_never_contains_metrics():
    s = Served(token="t0ken")
    try:
        _, body, _ = s.get("/metrics")
        assert "syshealth_" not in body
    finally:
        s.close()


def test_slow_client_does_not_block_other_requests(served):
    import socket
    idle = socket.create_connection(("127.0.0.1", served.server.server_address[1]))   # connects, sends nothing
    try:
        assert served.get("/metrics")[0] == 200
    finally:
        idle.close()


def test_graceful_shutdown_is_prompt_and_releases_port():
    s = Served()
    port = s.server.server_address[1]
    t0 = time.monotonic()
    s.close()
    assert time.monotonic() - t0 < 3 and not s.thread.is_alive()
    rebound = ex.make_server("127.0.0.1", port, s.collector)                 # port is free again
    rebound.server_close()


def test_sampler_thread_runs_and_stops_cleanly():
    calls = []
    c = ex.Collector(Config(), sample=0.0, refresh=0.2, collect_fn=lambda *a: calls.append(1) or rich_snap())
    t = ex.SamplerThread(c)
    t.start()
    time.sleep(0.6)
    t0 = time.monotonic()
    t.stop()
    assert len(calls) >= 2 and not t.is_alive() and time.monotonic() - t0 < 2


# ---- bind policy / token file ----------------------------------------------
@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.5", "::1", "localhost"])
def test_loopback_hosts_allowed_without_token(host):
    assert ex.validate_bind(host, 9877, False, None) == (None, None)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.5", "10.0.0.1", "example.com", ""])
def test_non_loopback_refused_by_default(host):
    with pytest.raises(ex.ExporterError, match="non-loopback"):
        ex.validate_bind(host, 9877, False, None)


def test_non_loopback_needs_both_flag_and_token(tmp_path):
    tok = tmp_path / "t"
    tok.write_text("abc123\n")
    os.chmod(tok, 0o600)
    with pytest.raises(ex.ExporterError, match="requires --token-file"):
        ex.validate_bind("0.0.0.0", 9877, True, None)
    with pytest.raises(ex.ExporterError, match="non-loopback"):
        ex.validate_bind("0.0.0.0", 9877, False, str(tok))               # token alone is not consent
    assert ex.validate_bind("0.0.0.0", 9877, True, str(tok)) == ("abc123", None)


@pytest.mark.parametrize("port", [0, -1, 65536, 99999])
def test_invalid_ports_rejected(port):
    with pytest.raises(ex.ExporterError, match="port"):
        ex.validate_bind("127.0.0.1", port, False, None)


def test_token_file_validation(tmp_path):
    p = tmp_path / "t"
    with pytest.raises(ex.ExporterError, match="cannot read"):
        ex.read_token(str(p))
    p.write_text("  \n")
    with pytest.raises(ex.ExporterError, match="empty"):
        ex.read_token(str(p))
    p.write_text("two words")
    with pytest.raises(ex.ExporterError, match="whitespace"):
        ex.read_token(str(p))
    p.write_text("good-token\n")
    os.chmod(p, 0o644)
    token, warn = ex.read_token(str(p))
    assert token == "good-token" and "readable by other users" in warn
    os.chmod(p, 0o600)
    assert ex.read_token(str(p)) == ("good-token", None)


def test_run_rejects_bad_configuration_without_starting(capsys):
    cfg = Config()
    assert ex.run("0.0.0.0", 9877, cfg, 1.0, 15.0) == 2
    assert "non-loopback" in capsys.readouterr().err
    assert ex.run("127.0.0.1", 9877, cfg, 5.0, 1.0) == 2
    assert "--refresh must be >= --sample" in capsys.readouterr().err


def test_run_reports_port_in_use(capsys):
    blocker = ex.make_server("127.0.0.1", 0, make_collector(lambda *a: rich_snap()))
    try:
        port = blocker.server_address[1]
        assert ex.run("127.0.0.1", port, Config(), 0.1, 1.0) == 2
        assert "cannot listen" in capsys.readouterr().err
    finally:
        blocker.server_close()
