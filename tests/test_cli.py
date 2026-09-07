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

    result = runner.invoke(app, [*_run_args(tmp_path), "--auto"])
    assert result.exit_code == 0, result.output
    assert "NOT running as root" in result.output
    assert "sudo cableprobe run" in result.output


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


def test_check_mentions_sudo_when_not_root(monkeypatch):
    monkeypatch.setattr("cableprobe.cli._is_root", lambda: False)
    result = runner.invoke(app, ["check"])
    assert "not running as root" in result.output
    assert "sudo cableprobe check" in result.output
