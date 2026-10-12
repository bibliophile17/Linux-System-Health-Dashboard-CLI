# syshealth — Linux System Health Dashboard

[![CI](https://github.com/bibliophile17/Linux-System-Health-Dashboard-CLI/actions/workflows/ci.yml/badge.svg)](https://github.com/bibliophile17/Linux-System-Health-Dashboard-CLI/actions/workflows/ci.yml)

A read-only Linux health monitor with alerting, diagnostics and JSON incident reports.
It reads `/proc` directly, needs **no root** and has **no third-party runtime dependencies** (Python standard library only).

> **Linux only.** It reads `/proc`. On Windows, develop and run it inside WSL2 (see below).

## Install

```bash
git clone https://github.com/bibliophile17/Linux-System-Health-Dashboard-CLI.git
cd Linux-System-Health-Dashboard-CLI
python3 -m venv .venv && source .venv/bin/activate     # Python 3.11+
pip install -e ".[dev]"                                # dev = pytest + ruff; the tool itself needs nothing
```

Or run without installing: `python3 -m syshealth show`.

## Commands

```bash
syshealth show                       # one-shot snapshot + alerts
syshealth show --findings            # ... plus read-only diagnostics
syshealth watch -i 5                 # refresh every 5 s (Ctrl+C to stop); --json = one JSON object per line
syshealth check                      # alerts only; exit code reflects severity
syshealth diagnose [--all] [--json]  # observations, hypotheses, follow-up commands
syshealth incident -o report.json    # JSON incident report (refuses to overwrite without --force)
syshealth analyze [--json]           # ranked likely causes (rule-based, hedged)
syshealth cpu | memory | disk | network | processes [-n 15] [--by mem]
```

Useful options: `--sample SEC` (window for rates, default 1), `--no-color`, `--json`, `--config FILE`,
`--warn METRIC=VALUE`, `--crit METRIC=VALUE`, `--state-file FILE`, `--alert-log FILE`,
`--no-commands` (never run external programs), `incident --include-logs N` (redacted journal lines, opt-in).

### Exit codes (`show`, `check`, `diagnose`, `incident`)

| Code | Meaning |
|---|---|
| 0 | healthy (or only informational findings) |
| 1 | a warning is active |
| 2 | a critical is active, **or** a usage/config error |
| 3 | monitoring itself failed (no metrics could be read) |
| 130 | interrupted with Ctrl+C |

## How it measures

- **CPU %** comes from the *difference* between two `/proc/stat` readings, never from since-boot totals.
- **Memory** used = `MemTotal - MemAvailable`; shown as `n/a` if the kernel doesn't report `MemAvailable`.
- **Process CPU %** is relative to one core (100 = one fully busy core), only for processes seen in both samples.
- **Disk %** matches `df`; pseudo filesystems are skipped.
- **Missing data is `n/a` / `null`, never `0`.** A metric that can't be read also never "resolves" an existing alert.

## Alerting

Thresholds come from built-in defaults, an optional TOML file (`--config`, see
[`examples/syshealth.toml`](examples/syshealth.toml)) and `--warn`/`--crit` overrides, validated at startup.
Metrics: `cpu_percent`, `memory_percent`, `swap_percent`, `disk_percent` (per mount), `load_per_core`, `process_count`.

- Events fire only on **transitions** (`opened`, `escalated`, `deescalated`, `resolved`), so a persistent condition alerts once.
- A small hysteresis band (default 3%) stops flapping around a threshold.
- `--state-file` carries state between runs (e.g. from cron); `--alert-log` appends transitions as JSON lines.

## Diagnostics (all read-only)

`diagnose` covers CPU, memory, disk space, disk I/O, process count, failed services, TCP ports/connection states and
interface errors. Every finding separates **observations** (measured facts), **hypotheses** (hedged, unverified),
**follow-up commands** (read-only; shown, never executed) and **limitations**.
The only external programs ever run are `systemctl --failed` and (opt-in) `journalctl -p err`, with no shell.
Pass `--no-commands` to avoid even those. Some heuristic thresholds (disk-busy %, pressure %, socket-state counts)
are fixed constants in `syshealth/diagnostics.py`.

## Incident analysis (rule-based, read-only)

```bash
syshealth analyze [--json] [--no-commands]   # ranked, hedged likely causes built from the diagnostics
python -m syshealth.analysis_eval --split dev -v   # reproducible evaluation on the synthetic dataset
```

`analyze` reuses the `diagnose` findings (no duplicated rules) and ranks causes by evidence strength. Output separates
observations from hypotheses, lists what was *not* assessed, ranks root cause before consequence (e.g. an OOM-killed
service after memory pressure), and abstains (`inconclusive` / `insufficient_data`) rather than guessing. Confidence is an
evidence-strength label, not a probability. Suggested commands are printed for you to run; nothing is executed.
Examples: [`examples/example-analysis.md`](examples/example-analysis.md).

Evaluation: [`docs/analysis-evaluation.md`](docs/analysis-evaluation.md) defines the criteria (written before the code),
and records results on 29 labelled **synthetic** cases (`eval/incidents.json`, hash-frozen). The rules pass all of them,
but the cases were written by the same author, so this shows consistency and abstention behaviour, not real-world
accuracy.

**Ollama / local-model backend: not implemented.** There is no measurement showing a model would improve on the
baseline (none could be run in the development environment), and the baseline already scores 100% on its own dataset,
so the dataset cannot show an improvement either. See the roadmap.

## Optional monitoring (Prometheus + Grafana)

```bash
syshealth exporter            # http://127.0.0.1:9877/metrics (loopback only by default)
```

Ships with a Prometheus scrape config and alert rules, a Grafana dashboard, an optional Docker Compose stack
(loopback only) and a hardened systemd unit under [`monitoring/`](monitoring/). Setup, security model, metric list and
cleanup commands: **[docs/monitoring.md](docs/monitoring.md)**. The core CLI never needs any of this.

Validation status: the exporter is unit- and integration-tested (real sockets), and the YAML/JSON files are checked
for structure and for agreement with the metric names the exporter emits. They have **not** been run through
`promtool`, a real Prometheus/Grafana, or Docker in CI, so expect to adjust on first use.

## Privacy

Reports contain hostname, kernel, process **names** and resource figures only: no command lines, environment
variables or file contents. Journal lines are included only with `--include-logs` and are redacted best-effort;
review a report before sharing it.

## Development

```bash
python -m pytest -q          # no root; most tests use fake /proc trees
ruff check .                 # lint
```

CI (`.github/workflows/ci.yml`) runs ruff, the tests on Python 3.11–3.13 on Ubuntu 22.04/24.04, and a smoke test
against the runner's real `/proc`. It uses no secrets.

### Windows (VS Code + WSL2)

Install the *WSL* extension, open the folder with **WSL: Reopen Folder in WSL**, then use the commands above in the
integrated terminal. Running natively on Windows is not supported.

## Layout

```
syshealth/  analysis.py  analysis_eval.py  collectors.py  evidence.py  diagnostics.py  alerts.py  config.py  report.py  export.py  exporter.py  render.py  cli.py
tests/      deterministic tests using fake /proc trees and synthetic snapshots
examples/   syshealth.toml
monitoring/ Prometheus, Grafana, Docker Compose, systemd (optional)
docs/       monitoring.md  analysis-evaluation.md
eval/       incidents.json (synthetic, frozen)  results.json
```

## Roadmap

- [x] 1 Audit
- [x] 2 Core: `/proc` collectors, delta CPU, graceful missing data
- [x] 3 Config, alerting, JSON output
- [x] 4 Diagnostics and incident reports
- [x] 5 CI
- [x] 6 Prometheus / Grafana (optional)
- [x] 7a Deterministic incident analysis + evaluation
- [ ] 7b Optional local-model (Ollama) backend: awaiting decision, see README
- [ ] 8 Final documentation pass and clean-install check
