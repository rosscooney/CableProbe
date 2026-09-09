# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from datetime import datetime, timezone

from typer.testing import CliRunner

from cableprobe.cli import app
from cableprobe.models import PhaseObservation, SessionMetadata, SessionReport, SystemSnapshot

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "cableprobe" in result.stdout


def test_probes_command():
    result = runner.invoke(app, ["probes"])
    assert result.exit_code == 0
    assert "udev_monitor" in result.stdout
    assert "kernel_log" in result.stdout


def test_rules_command_default():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "hid-keyboard-appeared-on-connect" in result.stdout


def test_check_runs():
    result = runner.invoke(app, ["check"])
    # exit code may be 1 on non-Linux (probes unavailable) - that's fine
    assert result.exit_code in (0, 1)
    assert "Probes" in result.stdout


def _fake_report() -> SessionReport:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    empty = SystemSnapshot(timestamp=now, observations=[])
    phase = PhaseObservation(
        phase="baseline",
        started_at=now,
        ended_at=now,
        start_snapshot=empty,
        end_snapshot=empty,
    )
    meta = SessionMetadata(
        session_name="fake",
        cableprobe_version="0.1.0",
        started_at=now,
        ended_at=now,
        interactive=False,
        host={"node": "pi"},
    )
    return SessionReport(
        metadata=meta,
        phases={"baseline": phase, "test": phase, "post_test": phase},
        deltas=[],
        findings=[],
        summary={"highest_severity": None, "finding_count": 0},
    )


def test_run_command_writes_report(tmp_path, monkeypatch):
    async def fake_run_session(*args, **kwargs):
        return _fake_report()

    monkeypatch.setattr("cableprobe.cli.run_session", fake_run_session)

    result = runner.invoke(
        app,
        [
            "run",
            "--auto",
            "--baseline",
            "1",
            "--test",
            "1",
            "--post-test",
            "1",
            "--output-dir",
            str(tmp_path),
            "--name",
            "clitest",
        ],
    )
    assert result.exit_code == 0, result.output
    written = list(tmp_path.glob("*.cableprobe.json"))
    assert len(written) == 1
    assert "report written to" in result.output


def test_report_command_json(tmp_path, monkeypatch):
    from cableprobe.report import write_report

    path = write_report(_fake_report(), tmp_path)
    result = runner.invoke(app, ["report", str(path), "--format", "json"])
    assert result.exit_code == 0
    assert '"session_name": "fake"' in result.stdout


def test_report_command_picker_lists_and_selects(tmp_path):
    from cableprobe.report import write_report

    for name in ("alpha", "bravo", "charlie"):
        r = _fake_report()
        r.metadata.session_name = name
        write_report(r, tmp_path, filename=f"2026010{len(name)}T000000Z-{name}.cableprobe.json")

    result = runner.invoke(app, ["report", "--output-dir", str(tmp_path)], input="2\n")
    assert result.exit_code == 0, result.output
    assert "Saved reports in" in result.output
    assert "1." in result.output and "3." in result.output
    # newest filename first -> charlie (…7…), bravo (…5…), alpha (…5? -> alpha len4)
    # just assert the selected one got rendered
    assert "CableProbe session report" not in result.output  # rich path
    assert "What this means" in result.output


def test_report_command_picker_out_of_range(tmp_path):
    from cableprobe.report import write_report

    write_report(_fake_report(), tmp_path, filename="20260101T000000Z-x.cableprobe.json")
    result = runner.invoke(app, ["report", "--output-dir", str(tmp_path)], input="9\n")
    assert result.exit_code == 2
    assert "out of range" in result.output


def test_report_command_picker_empty_dir(tmp_path):
    result = runner.invoke(app, ["report", "--output-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert "no saved reports" in result.output


def test_link_creates_and_removes_symlink(tmp_path, monkeypatch):
    from pathlib import Path

    launcher = tmp_path / "src" / "cableprobe"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    bindir = tmp_path / "bin"
    monkeypatch.setattr("cableprobe.cli._launcher_path", lambda: launcher)

    result = runner.invoke(app, ["link", "--bin-dir", str(bindir)])
    assert result.exit_code == 0, result.output
    link = bindir / "cableprobe"
    assert link.is_symlink() and link.resolve() == launcher.resolve()
    assert "works without a full path" in result.output

    # idempotent
    again = runner.invoke(app, ["link", "--bin-dir", str(bindir)])
    assert again.exit_code == 0
    assert "already points at" in again.output

    removed = runner.invoke(app, ["link", "--bin-dir", str(bindir), "--remove"])
    assert removed.exit_code == 0
    assert not link.exists()

    noop = runner.invoke(app, ["link", "--bin-dir", str(bindir), "--remove"])
    assert noop.exit_code == 0
    assert "nothing to remove" in noop.output


def test_link_reports_permission_error(tmp_path, monkeypatch):
    launcher = tmp_path / "cableprobe"
    launcher.write_text("x", encoding="utf-8")
    monkeypatch.setattr("cableprobe.cli._launcher_path", lambda: launcher)
    monkeypatch.setattr("cableprobe.cli._is_root", lambda: False)

    def boom(*a, **k):
        raise PermissionError("nope")

    monkeypatch.setattr("pathlib.Path.symlink_to", boom)
    result = runner.invoke(app, ["link", "--bin-dir", str(tmp_path / "bin")])
    assert result.exit_code == 1
    assert "could not write" in result.output
    assert "sudo" in result.output and "link" in result.output


def test_run_rejects_bad_config(tmp_path):
    bad = tmp_path / "c.yaml"
    bad.write_text("session: {test_seconds: -5}\n", encoding="utf-8")
    result = runner.invoke(app, ["run", "--auto", "--config", str(bad)])
    assert result.exit_code == 2


def _run_args(tmp_path):
    return [
        "run", "--baseline", "1", "--test", "1", "--post-test", "1",
        "--output-dir", str(tmp_path), "--name", "clitest",
    ]


def test_run_warns_when_not_root_but_continues_in_auto(tmp_path, monkeypatch):
    async def fake_run_session(*a, **k):
        return _fake_report()

    monkeypatch.setattr("cableprobe.cli.run_session", fake_run_session)
    monkeypatch.setattr("cableprobe.cli._is_root", lambda: False)
    # launcher on root's PATH -> the plain hint
    monkeypatch.setattr(
        "cableprobe.cli._launcher_path", lambda: __import__("pathlib").Path("/usr/local/bin/cableprobe")
    )

    result = runner.invoke(app, [*_run_args(tmp_path), "--auto"])
    assert result.exit_code == 0, result.output
    assert "NOT running as root" in result.output
    assert "sudo cableprobe run" in result.output


def test_sudo_hints_for_user_local_install(monkeypatch):
    from pathlib import Path

    from cableprobe.cli import _sudo_hints

    monkeypatch.setattr(
        "cableprobe.cli._launcher_path", lambda: Path("/home/pi/.local/bin/cableprobe")
    )
    hints = _sudo_hints("check")
    assert hints[0] == "sudo /home/pi/.local/bin/cableprobe check"
    assert any('env "PATH=$PATH"' in h for h in hints)
    assert any(h.endswith("cableprobe link") for h in hints)

    monkeypatch.setattr(
        "cableprobe.cli._launcher_path", lambda: Path("/usr/local/bin/cableprobe")
    )
    assert _sudo_hints("check") == ["sudo cableprobe check"]

    monkeypatch.setattr("cableprobe.cli._launcher_path", lambda: None)
    assert _sudo_hints("run") == ["sudo cableprobe run …"]


def test_run_interactive_aborts_when_operator_declines_sudo(tmp_path, monkeypatch):
    async def fake_run_session(*a, **k):
        return _fake_report()

    monkeypatch.setattr("cableprobe.cli.run_session", fake_run_session)
    monkeypatch.setattr("cableprobe.cli._is_root", lambda: False)

    result = runner.invoke(app, _run_args(tmp_path), input="n\n")
    assert result.exit_code == 1
    assert "re-run with sudo" in result.output
    assert not list(tmp_path.glob("*.cableprobe.json"))


def test_run_interactive_continues_when_operator_accepts(tmp_path, monkeypatch):
    async def fake_run_session(*a, **k):
        return _fake_report()

    monkeypatch.setattr("cableprobe.cli.run_session", fake_run_session)
    monkeypatch.setattr("cableprobe.cli._is_root", lambda: False)

    result = runner.invoke(app, _run_args(tmp_path), input="y\n")
    assert result.exit_code == 0, result.output
    assert len(list(tmp_path.glob("*.cableprobe.json"))) == 1


def test_run_as_root_has_no_sudo_warning(tmp_path, monkeypatch):
    async def fake_run_session(*a, **k):
        return _fake_report()

    monkeypatch.setattr("cableprobe.cli.run_session", fake_run_session)
    monkeypatch.setattr("cableprobe.cli._is_root", lambda: True)

    result = runner.invoke(app, [*_run_args(tmp_path), "--auto"])
    assert result.exit_code == 0, result.output
    assert "NOT running as root" not in result.output


def test_phase_progress_plain_falls_back_to_text_lines(capsys):
    from cableprobe.cli import _PhaseProgress

    p = _PhaseProgress(plain=True)
    p.tick("baseline", 1.0, 2.0)
    p.tick("baseline", 2.0, 2.0)
    p.close()
    out = capsys.readouterr().out
    assert "[baseline]" in out and "100%" in out


def test_phase_progress_bar_runs_through_three_phases():
    from cableprobe.cli import _PhaseProgress

    p = _PhaseProgress()
    for phase, dur in (("baseline", 2.0), ("test", 3.0), ("post_test", 2.0)):
        for step in (1.0, 2.0, dur):
            p.tick(phase, min(step, dur), dur)
    # each phase closed its own bar as it hit 100%; a final close is a no-op
    assert p._progress is None
    p.close()


def test_check_mentions_sudo_when_not_root(monkeypatch):
    from pathlib import Path

    monkeypatch.setattr("cableprobe.cli._is_root", lambda: False)
    monkeypatch.setattr(
        "cableprobe.cli._launcher_path", lambda: Path("/usr/local/bin/cableprobe")
    )
    result = runner.invoke(app, ["check"])
    assert "not running as root" in result.output
    assert "sudo cableprobe check" in result.output
