"""The shipped Prometheus/Grafana/compose files must agree with what the exporter really emits."""
import json
import pathlib
import re

import pytest
import yaml
from helpers import make_snap

import syshealth
from syshealth import exporter as ex
from syshealth.alerts import AlertEngine
from syshealth.collectors import NetIface
from syshealth.config import Config

ROOT = pathlib.Path(__file__).resolve().parent.parent
MON = ROOT / "monitoring"
METRIC = re.compile(r"\bsyshealth_[a-z0-9_]+")


def emitted_metric_names():
    snap = make_snap(cpu=42.0, mem=60.0, swap=10.0, disks={"/": 30, "/data": 95})
    snap.network = [NetIface("eth0", 1, 1, 1, 1, 1, 1, 1, 1)]
    snap.unavailable = ["loadavg"]
    eng = AlertEngine(Config())
    eng.evaluate(snap)
    c = ex.Collector(Config(), 0.0, 15.0, collect_fn=lambda *a: snap)
    c.run_once()
    text = c.scrape()[1]
    return set(re.findall(r"^# TYPE (\S+) ", text, re.M))


def load_yaml(rel):
    return yaml.safe_load((MON / rel).read_text())


def referenced(expr):
    return set(METRIC.findall(expr))


# ---- Prometheus -------------------------------------------------------------
def test_scrape_config_targets_loopback_exporter_port():
    cfg = load_yaml("prometheus/prometheus.yml")
    job = next(j for j in cfg["scrape_configs"] if j["job_name"] == "syshealth")
    targets = job["static_configs"][0]["targets"]
    assert targets == [f"127.0.0.1:{ex.DEFAULT_PORT}"]
    assert cfg["rule_files"] == ["alerts.yml"] and (MON / "prometheus/alerts.yml").exists()


def test_alert_rules_are_well_formed_and_reference_real_metrics():
    rules = load_yaml("prometheus/alerts.yml")["groups"][0]["rules"]
    names = emitted_metric_names()
    assert len(rules) >= 8 and len({r["alert"] for r in rules}) == len(rules)
    for r in rules:
        assert {"alert", "expr", "labels", "annotations"} <= set(r), r["alert"]
        assert r["labels"]["severity"] in ("info", "warning", "critical"), r["alert"]
        assert r["annotations"]["summary"] and r["annotations"]["description"]
        refs = referenced(r["expr"])
        assert refs or "up{" in r["expr"], r["alert"]
        assert refs <= names, f"{r['alert']} references unknown metrics: {refs - names}"
        assert r["expr"].count("(") == r["expr"].count(")") and r["expr"].count("[") == r["expr"].count("]")


def test_alert_thresholds_agree_with_default_config():
    rules = {r["alert"]: r for r in load_yaml("prometheus/alerts.yml")["groups"][0]["rules"]}
    crit_disk = Config().thresholds["disk_percent"][1] / 100
    assert f"> {crit_disk:g}" in rules["FilesystemNearlyFull"]["expr"]


# ---- Grafana ----------------------------------------------------------------
def dashboard():
    return json.loads((MON / "grafana/syshealth-dashboard.json").read_text())


def test_dashboard_structure_and_queries():
    d = dashboard()
    names = emitted_metric_names()
    ids = [p["id"] for p in d["panels"]]
    assert len(ids) == len(set(ids)) and len(ids) >= 10
    assert d["uid"] == "syshealth-overview" and d["schemaVersion"] >= 36
    assert [v["name"] for v in d["templating"]["list"]] == ["datasource"]
    for p in d["panels"]:
        assert p["datasource"]["uid"] == "${datasource}"
        assert p["targets"], p["title"]
        for t in p["targets"]:
            refs = referenced(t["expr"])
            assert refs and refs <= names, (p["title"], refs - names)
            assert t["datasource"]["uid"] == "${datasource}"
        g = p["gridPos"]
        assert g["x"] >= 0 and g["x"] + g["w"] <= 24 and g["h"] > 0


def test_dashboard_panels_do_not_overlap():
    boxes = [(p["gridPos"], p["title"]) for p in dashboard()["panels"]]
    for i, (a, ta) in enumerate(boxes):
        for b, tb in boxes[i + 1:]:
            overlap = a["x"] < b["x"] + b["w"] and b["x"] < a["x"] + a["w"] and a["y"] < b["y"] + b["h"] and b["y"] < a["y"] + a["h"]
            assert not overlap, (ta, tb)


# ---- Docker Compose / provisioning -----------------------------------------
def test_compose_binds_everything_to_loopback_and_pins_images():
    svc = load_yaml("docker-compose.yml")["services"]
    prom_cmd = " ".join(svc["prometheus"]["command"])
    assert "--web.listen-address=127.0.0.1:9090" in prom_cmd
    assert svc["grafana"]["environment"]["GF_SERVER_HTTP_ADDR"] == "127.0.0.1"
    for s in svc.values():
        assert re.search(r":v?\d+\.\d+\.\d+$", s["image"]), s["image"]           # pinned, not :latest
        assert "ports" not in s                                                  # nothing published on 0.0.0.0
    env = svc["grafana"]["environment"]
    assert env["GF_SECURITY_ADMIN_PASSWORD"].startswith("${GRAFANA_ADMIN_PASSWORD:?")   # required, no default
    assert str(env["GF_USERS_ALLOW_SIGN_UP"]).lower() == "false"


def test_compose_mounts_exist_and_datasource_points_at_loopback():
    for rel in ("prometheus", "grafana/provisioning", "grafana/syshealth-dashboard.json"):
        assert (MON / rel).exists(), rel
    ds = load_yaml("grafana/provisioning/datasources/prometheus.yml")["datasources"][0]
    assert ds["type"] == "prometheus" and ds["url"].startswith("http://127.0.0.1:9090")
    prov = load_yaml("grafana/provisioning/dashboards/syshealth.yml")["providers"][0]
    assert prov["options"]["path"] == "/var/lib/grafana/dashboards"


def test_no_secrets_committed_in_monitoring_files():
    for f in MON.rglob("*"):
        if f.is_file():
            text = f.read_text()
            assert not re.search(r"(?i)(password|token|secret)\s*[:=]\s*['\"]?[A-Za-z0-9]{6,}", text.replace("GRAFANA_ADMIN_PASSWORD", "")), f


# ---- systemd unit -----------------------------------------------------------
def test_systemd_unit_is_hardened_and_loopback():
    text = (MON / "syshealth-exporter.service").read_text()
    for must in ("DynamicUser=yes", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
                 "RestrictAddressFamilies=AF_INET AF_INET6", "--host 127.0.0.1"):
        assert must in text
    assert "User=root" not in text


# ---- housekeeping -----------------------------------------------------------
def test_version_is_consistent_between_package_and_pyproject():
    import tomllib
    assert tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"] == syshealth.__version__


def test_docs_mention_every_shipped_monitoring_file():
    doc = (ROOT / "docs/monitoring.md").read_text()
    for f in MON.rglob("*"):
        if f.is_file() and f.suffix in (".yml", ".json", ".service") and "provisioning" not in str(f):
            assert f.name in doc, f"docs/monitoring.md does not mention {f.name}"


@pytest.mark.parametrize("cmd", ["--token-file", "--allow-remote", "docker compose", "down -v", "systemctl disable"])
def test_docs_cover_setup_and_cleanup(cmd):
    assert cmd in (ROOT / "docs/monitoring.md").read_text()
