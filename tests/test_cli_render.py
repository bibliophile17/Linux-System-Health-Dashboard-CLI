import pytest

from syshealth import cli
from syshealth import collectors as c
from syshealth.render import SECTIONS, human_bytes, human_duration, render


def empty_snapshot(tmp_path):
    return c.collect(0.0, proc=str(tmp_path), sleep=lambda _: None)


def test_human_formatters():
    assert human_bytes(None) == "n/a"
    assert human_bytes(1536) == "1.5 KiB"
    assert human_duration(None) == "n/a" and human_duration(90061) == "1d 1h 1m"


def test_render_shows_na_for_missing_data(tmp_path):
    out = render(empty_snapshot(tmp_path), list(SECTIONS))
    assert "n/a" in out and "unavailable:" in out
    assert "\033[" not in out                       # no colour codes when disabled


def test_render_colour_only_when_requested(tmp_path):
    assert "\033[" in render(empty_snapshot(tmp_path), ["cpu"], color=True)


@pytest.mark.parametrize("argv", [["watch", "-i", "0"], ["watch", "-i", "abc"], ["show", "--sample", "-1"],
                                  ["processes", "-n", "0"], ["processes", "-n", "1000"], ["processes", "--by", "x"]])
def test_invalid_arguments_rejected(argv):
    with pytest.raises(SystemExit) as e:
        cli.build_parser().parse_args(argv)
    assert e.value.code == 2


def test_no_command_prints_help_and_exits_2(capsys):
    assert cli.main([]) == 2
    assert "usage" in capsys.readouterr().out.lower()


def test_ctrl_c_exits_cleanly(monkeypatch, capsys):
    def boom(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "collect", boom)
    assert cli.main(["show"]) == 130
    assert "stopped" in capsys.readouterr().err


def test_show_runs_against_fake_proc(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "collect", lambda *a, **k: empty_snapshot(tmp_path))
    # nothing readable -> still renders every section, but exit code 3 says "monitoring failed"
    assert cli.main(["show", "--no-color"]) == 3
    assert "== CPU" in capsys.readouterr().out
