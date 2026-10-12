"""Command-line entry point (argparse, stdlib only).

Exit codes:  0 ok | 1 warning active | 2 critical active (or usage/config error)
             3 monitoring itself failed (no metrics could be read)
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import sys
import time

from . import __version__
from .alerts import AlertEngine, append_log, load_state, save_state
from .analysis import analyze, render_analysis
from .collectors import Snapshot, collect
from .config import Config, ConfigError, apply_overrides, load_config
from .diagnostics import Finding, highest, run_diagnostics
from .evidence import gather, read_journal_errors
from .export import dumps, report_dict
from .exporter import DEFAULT_HOST, DEFAULT_PORT
from .exporter import run as run_exporter
from .render import SECTIONS, render, render_findings
from .report import build_incident, write_exclusive

EXIT = {"ok": 0, "warning": 1, "critical": 2}


def _bounded_float(text: str) -> float:
    try:
        v = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not 0.1 <= v <= 3600:
        raise argparse.ArgumentTypeError("must be between 0.1 and 3600")
    return v


def _bounded_int(text: str) -> int:
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {text!r}") from None
    if not 1 <= v <= 100:
        raise argparse.ArgumentTypeError("must be between 1 and 100")
    return v


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="syshealth", description="Linux system health dashboard (reads /proc, read-only).")
    p.add_argument("--version", action="version", version=f"syshealth {__version__}")
    sub = p.add_subparsers(dest="command", metavar="command")

    def thresholds(sp) -> None:
        sp.add_argument("--config", metavar="FILE", help="TOML threshold file (see examples/syshealth.toml)")
        sp.add_argument("--warn", action="append", default=[], metavar="METRIC=VALUE",
                        help="override a warning threshold, e.g. --warn cpu=70 (repeatable)")
        sp.add_argument("--crit", action="append", default=[], metavar="METRIC=VALUE",
                        help="override a critical threshold (repeatable)")

    def common(sp, alerting: bool = False) -> None:
        sp.add_argument("--sample", type=_bounded_float, default=1.0, metavar="SEC",
                        help="seconds between the two samples used for rates (default 1.0)")
        sp.add_argument("--no-color", action="store_true", help="disable ANSI colour")
        if alerting:
            thresholds(sp)
            sp.add_argument("--json", action="store_true", help="machine-readable JSON on stdout")
            sp.add_argument("--state-file", metavar="FILE",
                            help="persist alert state between runs (dedupes across invocations)")
            sp.add_argument("--alert-log", metavar="FILE", help="append alert transitions as JSON lines")

    show = sub.add_parser("show", help="one-shot snapshot of everything, with alerts")
    common(show, True)
    show.add_argument("-n", "--count", type=_bounded_int, default=5, help="processes to list (default 5)")
    show.add_argument("--findings", action="store_true", help="also run read-only diagnostics (no external commands)")
    diag = sub.add_parser("diagnose", help="read-only diagnostics: observations, hypotheses and follow-up commands")
    common(diag)
    thresholds(diag)
    diag.add_argument("--json", action="store_true", help="machine-readable JSON on stdout")
    diag.add_argument("--all", action="store_true", help="also show checks that found nothing")
    diag.add_argument("--no-commands", action="store_true",
                      help="never run external programs (skips the systemd check)")
    ana = sub.add_parser("analyze", help="rank likely causes from diagnostics (rule-based, read-only, hypotheses only)")
    common(ana)
    thresholds(ana)
    ana.add_argument("--json", action="store_true", help="machine-readable JSON on stdout")
    ana.add_argument("--no-commands", action="store_true",
                     help="never run external programs (skips the systemd check)")
    inc = sub.add_parser("incident", help="write a JSON incident report (diagnostics + alerts + snapshot)")
    common(inc)
    thresholds(inc)
    inc.add_argument("-o", "--output", default="-", metavar="FILE", help="report path, or - for stdout (default)")
    inc.add_argument("--force", action="store_true", help="overwrite the output file if it exists")
    inc.add_argument("--no-commands", action="store_true", help="never run external programs")
    inc.add_argument("--include-logs", type=int, default=0, metavar="N",
                     help="include the last N error-level journal lines, redacted (0-200, default 0 = none)")
    inc.add_argument("--state-file", metavar="FILE", help="persist alert state between runs")
    check = sub.add_parser("check", help="evaluate alerts only; exit code reflects worst severity")
    common(check, True)
    watch = sub.add_parser("watch", help="refresh repeatedly; Ctrl+C to stop (--json prints one object per line)")
    common(watch, True)
    watch.add_argument("-i", "--interval", type=_bounded_float, default=5.0,
                       help="seconds between refreshes (default 5)")
    watch.add_argument("-n", "--count", type=_bounded_int, default=5)
    exp = sub.add_parser("exporter", help="serve Prometheus metrics (optional; loopback only by default)")
    common(exp)
    thresholds(exp)
    exp.add_argument("--host", default=DEFAULT_HOST, help=f"address to bind (default {DEFAULT_HOST})")
    exp.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default {DEFAULT_PORT})")
    exp.add_argument("--refresh", type=_bounded_float, default=15.0, metavar="SEC",
                     help="seconds between background collections (default 15)")
    exp.add_argument("--allow-remote", action="store_true", help="permit a non-loopback --host (requires --token-file)")
    exp.add_argument("--token-file", metavar="FILE", help="file holding a bearer token clients must send")
    for name in SECTIONS:
        sp = sub.add_parser(name, help=f"show {name} only")
        common(sp)
        if name == "processes":
            sp.add_argument("-n", "--count", type=_bounded_int, default=10)
            sp.add_argument("--by", choices=("cpu", "mem"), default="cpu")
    return p


def _warn(msg: str) -> None:
    print(f"syshealth: warning: {msg}", file=sys.stderr)


def _persist(args, engine: AlertEngine, events: list[dict]) -> None:
    """Best effort: failing to write state/log must never break monitoring."""
    try:
        if args.state_file:
            save_state(args.state_file, engine.state)
        if args.alert_log:
            append_log(args.alert_log, events)
    except OSError as e:
        _warn(f"could not write state/log: {e.strerror or e}")


def _load_cfg(args) -> Config:
    return apply_overrides(load_config(args.config), args.warn, args.crit)


def _exit_for(findings: list[Finding], snap: Snapshot) -> int:
    if _failed(snap):
        return 3
    return {"critical": 2, "warning": 1}.get(highest(findings), 0)


def _failed(snap: Snapshot) -> bool:
    return snap.cpu_percent is None and snap.memory is None and snap.process_count is None


def _alert_cycle(args, cfg: Config, engine: AlertEngine, snap: Snapshot) -> list[dict]:
    events = engine.evaluate(snap)
    _persist(args, engine, events)
    return events


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    color = sys.stdout.isatty() and not args.no_color
    try:
        if args.command in SECTIONS:
            snap = collect(args.sample, getattr(args, "count", 5))
            print(render(snap, [args.command], color, getattr(args, "by", "cpu")))
            return 0

        try:
            cfg = _load_cfg(args)
        except ConfigError as e:
            print(f"syshealth: config error: {e}", file=sys.stderr)
            return 2

        if args.command == "exporter":
            return run_exporter(args.host, args.port, cfg, args.sample, args.refresh,
                                args.allow_remote, args.token_file)

        if args.command == "diagnose":
            ev = gather(args.sample, 5, run_commands=not args.no_commands)
            findings = run_diagnostics(ev, cfg)
            if args.json:
                print(dumps({"schema_version": 1, "status": highest(findings),
                             "findings": [dataclasses.asdict(f) for f in findings]}))
            else:
                print(render_findings(findings, color, args.all))
            return _exit_for(findings, ev.snap)

        if args.command == "analyze":
            ev = gather(args.sample, 5, run_commands=not args.no_commands)
            findings = run_diagnostics(ev, cfg)
            result = analyze(findings, ev, cfg)
            if args.json:
                print(dumps({"schema_version": 1, "analysis": result.to_dict()}))
            else:
                print(render_analysis(result))
            return _exit_for(findings, ev.snap)

        engine = AlertEngine(cfg, load_state(args.state_file) if args.state_file else None)

        if args.command == "incident":
            if not 0 <= args.include_logs <= 200:
                print("syshealth: --include-logs must be between 0 and 200", file=sys.stderr)
                return 2
            ev = gather(args.sample, 5, run_commands=not args.no_commands)
            findings = run_diagnostics(ev, cfg)
            engine.evaluate(ev.snap)
            _persist(argparse.Namespace(state_file=getattr(args, "state_file", None), alert_log=None), engine, [])
            logs = read_journal_errors(args.include_logs) if args.include_logs and not args.no_commands else None
            text = dumps(build_incident(ev, findings, engine, cfg, logs, logs_requested=args.include_logs > 0))
            if args.output == "-":
                print(text)
            else:
                try:
                    write_exclusive(args.output, text, args.force)
                except FileExistsError:
                    print(f"syshealth: {args.output} exists; use --force to overwrite", file=sys.stderr)
                    return 2
                except OSError as e:
                    print(f"syshealth: cannot write {args.output}: {e.strerror or e}", file=sys.stderr)
                    return 2
                print(f"incident report written to {args.output}")
            return _exit_for(findings, ev.snap)

        if args.command == "watch":
            recent: collections.deque = collections.deque(maxlen=5)
            interactive = sys.stdout.isatty() and not args.json
            while True:
                snap = collect(args.sample, args.count)
                recent.extend(_alert_cycle(args, cfg, engine, snap))
                if args.json:
                    print(dumps(report_dict(snap, engine, list(recent), cfg), pretty=False), flush=True)
                else:
                    if interactive:
                        sys.stdout.write("\033[H\033[2J")  # clear only on a real terminal
                    print(render(snap, list(SECTIONS), color, "cpu", cfg.thresholds, engine.active, list(recent)),
                          flush=True)
                time.sleep(max(0.0, args.interval - args.sample))

        findings = None
        if getattr(args, "findings", False):
            ev = gather(args.sample, getattr(args, "count", 5), run_commands=False)
            snap, findings = ev.snap, run_diagnostics(ev, cfg)
        else:
            snap = collect(args.sample, getattr(args, "count", 5))
        events = _alert_cycle(args, cfg, engine, snap)
        if args.json:
            print(dumps(report_dict(snap, engine, events, cfg, findings)))
        elif args.command == "show":
            print(render(snap, list(SECTIONS), color, "cpu", cfg.thresholds, engine.active, events))
            if findings is not None:
                print("\n" + render_findings(findings, color))
        else:  # check
            print(render(snap, [], color, "cpu", cfg.thresholds, engine.active, events))
        return 3 if _failed(snap) else EXIT[engine.worst]
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
        return 130
    except BrokenPipeError:  # e.g. `syshealth show | head`
        return 0
