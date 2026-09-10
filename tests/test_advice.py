# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from cableprobe.advice import build_advice
from cableprobe.models import Finding, SessionMetadata, SessionReport


def _report(findings: list[Finding], summary: dict) -> SessionReport:
    from datetime import datetime, timezone

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    meta = SessionMetadata(
        session_name="t",
        cableprobe_version="0",
        started_at=now,
        ended_at=now,
        interactive=True,
    )
    return SessionReport(metadata=meta, phases={}, findings=findings, summary=summary)


def _f(rule_id: str, severity: str) -> Finding:
    return Finding(rule_id=rule_id, title=rule_id, severity=severity)


def test_clean_session_advice_warns_against_false_confidence():
    a = build_advice(_report([], {"highest_severity": None}))
    assert a.severity == "none"
    body = " ".join(a.body).lower()
    assert "not the same as" in body and "dormant" in body


def test_keyboard_advice_is_high_and_explains_badusb():
    a = build_advice(
        _report(
            [_f("hid-keyboard-appeared-on-connect", "high")],
            {"highest_severity": "high"},
        )
    )
    assert a.severity == "high"
    body = " ".join(a.body).lower()
    assert "badusb" in body
    assert "do not trust or reuse this cable" in body


def test_network_adapter_advice_does_not_overclaim_routing():
    a = build_advice(
        _report(
            [_f("network-interface-appeared-on-connect", "high")],
            {"highest_severity": "high"},
        )
    )
    body = " ".join(a.body).lower()
    assert "network adapter" in body
    assert "did not take over routing" in body
    assert "active attack" not in body


def test_route_hijack_advice_supersedes_plain_network_theme():
    a = build_advice(
        _report(
            [
                _f("network-interface-appeared-on-connect", "high"),
                _f("default-route-changed-on-connect", "critical"),
            ],
            {"highest_severity": "critical"},
        )
    )
    joined = "\n".join(a.body)
    assert joined.count("network adapter") == 1  # only the hijack sentence
    assert "active attack" in joined
    assert "did not take over routing" not in joined


def test_critical_pci_advice_says_disconnect():
    a = build_advice(
        _report(
            [_f("pci-device-appeared-on-connect", "critical")],
            {"highest_severity": "critical"},
        )
    )
    assert "hostile hardware" in a.headline.lower()
    assert any("memory" in line.lower() for line in a.body)


def test_advice_mentions_each_distinct_theme_once():
    findings = [
        _f("network-interface-appeared-on-connect", "high"),
        _f("dns-resolvers-changed-on-connect", "critical"),
        _f("mass-storage-appeared-on-connect", "high"),
    ]
    a = build_advice(_report(findings, {"highest_severity": "critical"}))
    joined = "\n".join(a.body)
    assert joined.count("network adapter") == 1  # network theme collapsed
    assert "USB drive" in joined  # storage theme present


def test_advice_flags_non_reverted_state():
    a = build_advice(
        _report(
            [_f("mass-storage-appeared-on-connect", "high")],
            {"highest_severity": "high", "persisted_after_disconnect_count": 2},
        )
    )
    assert any("did not go away" in line.lower() for line in a.body)


def test_info_level_with_unmatched_changes_points_at_table():
    a = build_advice(
        _report(
            [],
            {"highest_severity": None, "cable_correlated_change_count": 3},
        )
    )
    assert any("3 small change" in line for line in a.body)
