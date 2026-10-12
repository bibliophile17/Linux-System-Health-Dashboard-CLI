"""Threshold configuration: defaults, TOML loading, CLI overrides, validation."""

from __future__ import annotations

import math
import tomllib
from dataclasses import dataclass, field, replace

# metric -> upper bound for its values (None = unbounded)
METRICS: dict[str, float | None] = {
    "cpu_percent": 100.0, "memory_percent": 100.0, "swap_percent": 100.0, "disk_percent": 100.0,
    "load_per_core": None, "process_count": None,
}
ALIASES = {"cpu": "cpu_percent", "memory": "memory_percent", "mem": "memory_percent", "swap": "swap_percent",
           "disk": "disk_percent", "load": "load_per_core", "procs": "process_count"}

# Illustrative defaults, not universal truths: tune them for your hosts.
DEFAULT_THRESHOLDS: dict[str, tuple[float, float]] = {
    "cpu_percent": (80.0, 95.0),
    "memory_percent": (85.0, 95.0),
    "swap_percent": (50.0, 80.0),
    "disk_percent": (80.0, 90.0),      # applied to each mounted filesystem
    "load_per_core": (1.0, 2.0),       # 1-minute load average / CPU count
    "process_count": (2000.0, 8000.0),
}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    thresholds: dict[str, tuple[float, float]] = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    # An alert only steps down once the value is this fraction below its threshold (anti-flapping).
    hysteresis: float = 0.03


def _number(value: object, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ConfigError(f"{what}: expected a finite number, got {value!r}")
    return float(value)


def _check_pair(metric: str, warn: float, crit: float) -> None:
    if warn < 0:
        raise ConfigError(f"{metric}: warn must be >= 0 (got {warn})")
    if warn >= crit:
        raise ConfigError(f"{metric}: warn ({warn}) must be lower than crit ({crit})")
    cap = METRICS[metric]
    if cap is not None and crit > cap:
        raise ConfigError(f"{metric}: crit ({crit}) cannot exceed {cap}")


def _canonical(name: str) -> str:
    name = ALIASES.get(name, name)
    if name not in METRICS:
        raise ConfigError(f"unknown metric {name!r}; valid: {', '.join(METRICS)}")
    return name


def parse_config(data: dict) -> Config:
    unknown = set(data) - {"hysteresis", "thresholds"}
    if unknown:
        raise ConfigError(f"unknown top-level key(s): {', '.join(sorted(unknown))}")
    thresholds = dict(DEFAULT_THRESHOLDS)
    table = data.get("thresholds", {})
    if not isinstance(table, dict):
        raise ConfigError("[thresholds] must be a table")
    for raw_name, entry in table.items():
        metric = _canonical(raw_name)
        if not isinstance(entry, dict) or set(entry) - {"warn", "crit"}:
            raise ConfigError(f"thresholds.{raw_name}: expected a table with only 'warn' and 'crit'")
        warn = _number(entry.get("warn", thresholds[metric][0]), f"{metric}.warn")
        crit = _number(entry.get("crit", thresholds[metric][1]), f"{metric}.crit")
        _check_pair(metric, warn, crit)
        thresholds[metric] = (warn, crit)
    hyst = _number(data.get("hysteresis", Config.hysteresis), "hysteresis")
    if not 0 <= hyst < 0.5:
        raise ConfigError(f"hysteresis must be in [0, 0.5), got {hyst}")
    return Config(thresholds, hyst)


def load_config(path: str | None) -> Config:
    if path is None:
        return Config()
    try:
        with open(path, "rb") as fh:
            return parse_config(tomllib.load(fh))
    except OSError as e:
        raise ConfigError(f"cannot read config {path}: {e.strerror or e}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"invalid TOML in {path}: {e}") from e


def apply_overrides(cfg: Config, warns: list[str], crits: list[str]) -> Config:
    """Apply repeated ``METRIC=VALUE`` command-line overrides on top of ``cfg``."""
    th = dict(cfg.thresholds)
    for kind, items in (("warn", warns), ("crit", crits)):
        for item in items:
            name, eq, raw = item.partition("=")
            if not eq:
                raise ConfigError(f"--{kind} expects METRIC=VALUE, got {item!r}")
            metric = _canonical(name.strip())
            try:
                value = float(raw)
            except ValueError:
                raise ConfigError(f"--{kind} {item}: {raw!r} is not a number") from None
            w, c = th[metric]
            th[metric] = (_number(value, item), c) if kind == "warn" else (w, _number(value, item))
    for metric, (w, c) in th.items():
        _check_pair(metric, w, c)
    return replace(cfg, thresholds=th)
