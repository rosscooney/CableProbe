# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from datetime import datetime, timezone

from cableprobe.analysis import analyse, build_summary
from cableprobe.models import (
    KIND_INPUT_DEVICE,
    SessionMetadata,
    SessionReport,
)
from cableprobe.report import exit_code_for, load_report, render_summary, write_report
from cableprobe.rules import RuleSet
from tests.conftest import obs


def _report(phase_builder) -> SessionReport:
    kb = obs(KIND_INPUT_DEVICE, "input:aaa", "Evil KB", ID_INPUT_KEYBOARD="1")
    phases = phase_builder(baseline_end=[], test_end=[kb], post_end=[])
    deltas = analyse(phases)
    findings = RuleSet.default().evaluate(deltas)
    summary = build_summary(phases, deltas, findings)
    meta = SessionMetadata(
        session_name="unit-test",
        cableprobe_version="0.1.0",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ended_at=datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc),
        interactive=False,
        host={"node": "testpi"},
        config={},
        probes_used=["usb", "input"],
    )
    return SessionReport(
        metadata=meta, phases=phases, deltas=deltas, findings=findings, summary=summary
    )


def test_write_and_load_roundtrip(tmp_path, phase_builder):
    report = _report(phase_builder)
    path = write_report(report, tmp_path)
    assert path.exists()
    assert path.suffix == ".json"
    loaded = load_report(path)
    assert loaded.metadata.session_name == "unit-test"
    assert loaded.model_dump() == report.model_dump()


def test_report_written_owner_only(tmp_path, phase_builder):
    import os
    import stat

    path = write_report(_report(phase_builder), tmp_path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_render_summary_escapes_device_markup(phase_builder, capsys):
    from cableprobe.models import KIND_USB_DEVICE
    from tests.conftest import obs as _obs

    evil = _obs(KIND_USB_DEVICE, "usb:1:2", "[red]spoofed[/red]")
    phases = phase_builder(baseline_end=[], test_end=[evil], post_end=[])
    from cableprobe.analysis import analyse, build_summary

    deltas = analyse(phases)
    report = _report(phase_builder)
    report.deltas = deltas
    report.summary = build_summary(phases, deltas, [])
    render_summary(report)  # rich path
    out = capsys.readouterr().out
    # the literal brackets survive; rich did not interpret them as a colour tag
    assert "[red]spoofed[/red]" in out


def test_exit_code_reflects_severity(phase_builder):
    report = _report(phase_builder)
    # keyboard rule is "high"
    assert exit_code_for(report) == 20


def test_render_summary_plain(phase_builder, capsys):
    report = _report(phase_builder)
    text = render_summary(report, plain=True)
    assert "CableProbe session report" in text
    assert "Evil KB" in text
    assert "HID keyboard appeared" in text


def test_summary_has_expected_keys(phase_builder):
    report = _report(phase_builder)
    for key in (
        "delta_count",
        "deltas_by_change",
        "deltas_by_kind",
        "cable_correlated_change_count",
        "finding_count",
        "findings_by_severity",
        "highest_severity",
    ):
        assert key in report.summary
    assert report.summary["highest_severity"] == "high"
