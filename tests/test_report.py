# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from datetime import datetime, timezone

from cableprobe.analysis import analyse, build_summary
from cableprobe.models import (
    KIND_INPUT_DEVICE,
    SessionMetadata,
    SessionReport,
)
import pytest

from cableprobe.report import (
    REPORT_INDEX_NAME,
    exit_code_for,
    load_report,
    read_report_index,
    render_summary,
    report_card_for,
    write_report,
)
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
        probes_unavailable=["usbc_pd: /sys/class/typec not present", "pci: no bus"],
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
    # the sidecar index carries the same session data -> same protection
    index_mode = stat.S_IMODE(os.stat(tmp_path / REPORT_INDEX_NAME).st_mode)
    assert index_mode == 0o600


def test_report_never_world_readable_even_under_loose_umask(tmp_path, phase_builder):
    import os
    import stat

    old = os.umask(0o000)  # would make write_text() create a 0o666 file
    try:
        path = write_report(_report(phase_builder), tmp_path)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_write_report_tightens_a_preexisting_loose_file(tmp_path, phase_builder):
    import os
    import stat

    stamp = "20260101T000000Z"
    victim = tmp_path / f"{stamp}-unit-test.cableprobe.json"
    victim.write_text("{}")
    os.chmod(victim, 0o666)
    write_report(_report(phase_builder), tmp_path)
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o600


def test_write_report_does_not_follow_a_symlinked_index(tmp_path, phase_builder):
    outside = tmp_path / "outside"
    outside.write_text("KEEP ME")
    (tmp_path / "sessions").mkdir()
    link = tmp_path / "sessions" / REPORT_INDEX_NAME
    link.symlink_to(outside)

    write_report(_report(phase_builder), tmp_path / "sessions")

    assert outside.read_text() == "KEEP ME"  # symlink target untouched
    assert not link.is_symlink()  # replaced by the real index file
    card = next(iter(read_report_index(tmp_path / "sessions").values()))
    assert card["session_name"] == "unit-test"


def test_load_report_refuses_a_symlinked_report(tmp_path, phase_builder):
    real = write_report(_report(phase_builder), tmp_path)
    secret = tmp_path / "secret"
    secret.write_text("SHADOW")
    link = tmp_path / "evil.cableprobe.json"
    link.symlink_to(secret)
    with pytest.raises(OSError):
        load_report(link)
    assert report_card_for(link, None) == {}  # picker degrades, does not read it
    load_report(real)  # the real one still loads


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


def test_loaded_report_cannot_inject_terminal_escapes(tmp_path, phase_builder):
    from cableprobe.models import Delta, Finding

    report = _report(phase_builder)
    report.deltas = [
        Delta(
            change="appeared",
            kind="usb_device",
            identity="usb:1:2",
            label="hidden\x1b[2Jkeyboard",
            first_seen_phase="test",
            present_in={"baseline": False, "test": True, "post_test": False},
        )
    ]
    report.findings = [
        Finding(rule_id="x", title="t\x1b[2J", severity="high",
                evidence=["line\x1b]0;title\x07"])
    ]
    report.metadata = report.metadata.model_copy(
        update={"session_name": "sess\x1b[2Sion", "probe_warnings": ["w\x1b[3J"]}
    )
    report.summary = {
        **report.summary,
        "coverage": "partial",
        "coverage_gaps": {"incomplete_data": ["/etc/\x1b[2Jhosts"]},
    }
    path = write_report(report, tmp_path)
    loaded = load_report(path)
    assert "\x1b" not in loaded.deltas[0].label
    assert "\x1b" not in loaded.findings[0].title
    assert "\x1b" not in "".join(loaded.findings[0].evidence)
    assert "\x1b" not in loaded.metadata.session_name
    assert "\x1b" not in "".join(loaded.metadata.probe_warnings)
    assert "\x1b" not in str(loaded.summary)
    assert "\x1b" not in render_summary(loaded, plain=True)


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


def test_not_enabled_probes_are_disclosed_not_silent(phase_builder, capsys):
    report = _report(phase_builder)
    report.metadata = report.metadata.model_copy(
        update={"probes_not_enabled": ["connections", "power", "wifi_scan"]}
    )

    plain = render_summary(report, plain=True)
    assert "not run:  connections, power, wifi_scan" in plain
    assert "power draw was not measured this session" in plain

    render_summary(report)  # rich path must not raise
    out = capsys.readouterr().out
    assert "Optional probes not enabled: connections, power, wifi_scan" in out
    assert "power draw was not measured this session" in out


def test_unavailable_probes_roundtrip_and_render(tmp_path, phase_builder, capsys):
    report = _report(phase_builder)
    loaded = load_report(write_report(report, tmp_path))
    assert loaded.metadata.probes_unavailable == report.metadata.probes_unavailable

    plain = render_summary(report, plain=True)
    assert "skipped:  usbc_pd, pci" in plain

    render_summary(report)  # rich path must not raise and names the skipped probes
    assert "usbc_pd, pci" in capsys.readouterr().out


def test_write_report_maintains_sidecar_index(tmp_path, phase_builder):
    path = write_report(_report(phase_builder), tmp_path)
    index = read_report_index(tmp_path)
    assert path.name in index
    card = index[path.name]
    assert card["session_name"] == "unit-test"
    assert card["highest_severity"] == "high"  # keyboard rule
    # the picker does not fall back to parsing the file when the index has it
    assert report_card_for(path, index) == card


def test_list_reports_falls_back_when_index_missing(tmp_path, phase_builder):
    path = write_report(_report(phase_builder), tmp_path)
    (tmp_path / REPORT_INDEX_NAME).unlink()
    card = report_card_for(path, read_report_index(tmp_path))
    assert card["session_name"] == "unit-test"
    assert card["highest_severity"] == "high"


def test_load_report_rejects_oversized_file(tmp_path, phase_builder, monkeypatch):
    import cableprobe.report as report_mod

    path = write_report(_report(phase_builder), tmp_path)
    monkeypatch.setattr(report_mod, "MAX_REPORT_BYTES", 10)
    with pytest.raises(ValueError, match="refusing to load"):
        load_report(path)
    # the picker degrades gracefully rather than raising
    assert report_card_for(path, None) == {}


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
