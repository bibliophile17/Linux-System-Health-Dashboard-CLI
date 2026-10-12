import os

import pytest

from syshealth.config import DEFAULT_THRESHOLDS, Config, ConfigError, apply_overrides, load_config, parse_config

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "syshealth.toml")


def toml(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text)
    return str(p)


def test_defaults_when_no_config():
    assert load_config(None) == Config() and Config().thresholds == DEFAULT_THRESHOLDS


def test_shipped_example_config_is_valid_and_matches_defaults():
    assert load_config(EXAMPLE).thresholds == DEFAULT_THRESHOLDS


def test_partial_override_keeps_other_defaults(tmp_path):
    cfg = load_config(toml(tmp_path, "[thresholds.cpu_percent]\nwarn = 60\ncrit = 70\n"))
    assert cfg.thresholds["cpu_percent"] == (60.0, 70.0)
    assert cfg.thresholds["disk_percent"] == DEFAULT_THRESHOLDS["disk_percent"]


def test_only_warn_given_uses_default_crit():
    cfg = parse_config({"thresholds": {"cpu": {"warn": 50}}})        # alias + partial
    assert cfg.thresholds["cpu_percent"] == (50.0, 95.0)


def test_hysteresis_value():
    assert parse_config({"hysteresis": 0.1}).hysteresis == 0.1


@pytest.mark.parametrize("data,fragment", [
    ({"bogus": 1}, "unknown top-level"),
    ({"thresholds": []}, "must be a table"),
    ({"thresholds": {"nope": {"warn": 1, "crit": 2}}}, "unknown metric"),
    ({"thresholds": {"cpu_percent": {"warn": 1, "crit": 2, "extra": 3}}}, "only 'warn' and 'crit'"),
    ({"thresholds": {"cpu_percent": 5}}, "expected a table"),
    ({"thresholds": {"cpu_percent": {"warn": 90, "crit": 80}}}, "must be lower"),
    ({"thresholds": {"cpu_percent": {"warn": 90, "crit": 90}}}, "must be lower"),
    ({"thresholds": {"cpu_percent": {"warn": 50, "crit": 101}}}, "cannot exceed"),
    ({"thresholds": {"cpu_percent": {"warn": -1, "crit": 50}}}, "must be >= 0"),
    ({"thresholds": {"cpu_percent": {"warn": "high", "crit": 90}}}, "finite number"),
    ({"thresholds": {"cpu_percent": {"warn": True, "crit": 90}}}, "finite number"),
    ({"thresholds": {"cpu_percent": {"warn": float("nan"), "crit": 90}}}, "finite number"),
    ({"thresholds": {"cpu_percent": {"warn": 1, "crit": float("inf")}}}, "finite number"),
    ({"hysteresis": 0.5}, "hysteresis"),
    ({"hysteresis": -0.1}, "hysteresis"),
    ({"hysteresis": "x"}, "finite number"),
])
def test_invalid_configs_rejected(data, fragment):
    with pytest.raises(ConfigError, match=fragment):
        parse_config(data)


def test_unbounded_metrics_may_exceed_100():
    cfg = parse_config({"thresholds": {"process_count": {"warn": 500, "crit": 1000}}})
    assert cfg.thresholds["process_count"] == (500.0, 1000.0)


def test_invalid_toml_and_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(toml(tmp_path, "this is = = not toml"))
    with pytest.raises(ConfigError, match="cannot read config"):
        load_config(str(tmp_path / "missing.toml"))


def test_directory_as_config_is_an_error_not_a_crash(tmp_path):
    with pytest.raises(ConfigError):
        load_config(str(tmp_path))


# ---- CLI overrides ----------------------------------------------------------
def test_overrides_applied_with_aliases():
    cfg = apply_overrides(Config(), ["cpu=70", "disk=60"], ["cpu=90"])
    assert cfg.thresholds["cpu_percent"] == (70.0, 90.0) and cfg.thresholds["disk_percent"] == (60.0, 90.0)


@pytest.mark.parametrize("warns,crits,fragment", [
    (["cpu"], [], "METRIC=VALUE"),
    (["cpu=abc"], [], "not a number"),
    (["cpu=nan"], [], "finite"),
    (["bogus=1"], [], "unknown metric"),
    (["cpu=99"], [], "must be lower"),              # new warn above existing crit (95)
    ([], ["cpu=70"], "must be lower"),              # new crit below existing warn (80)
    ([], ["cpu=150"], "cannot exceed"),
])
def test_invalid_overrides_rejected(warns, crits, fragment):
    with pytest.raises(ConfigError, match=fragment):
        apply_overrides(Config(), warns, crits)


def test_overrides_do_not_mutate_original():
    base = Config()
    apply_overrides(base, ["cpu=10"], [])
    assert base.thresholds["cpu_percent"] == DEFAULT_THRESHOLDS["cpu_percent"]
