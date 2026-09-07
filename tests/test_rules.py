# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from cableprobe.models import (
    KIND_BLOCK_DEVICE,
    KIND_INPUT_DEVICE,
    KIND_KERNEL_MESSAGE,
    KIND_NETWORK_INTERFACE,
    KIND_USB_DEVICE,
    Delta,
)
from cableprobe.rules import RuleSet


def _delta(kind, identity, *, change="appeared", first_seen_phase="test", **attrs) -> Delta:
    return Delta(
        change=change,
        kind=kind,
        identity=identity,
        label=attrs.pop("label", f"{kind} {identity}"),
        first_seen_phase=first_seen_phase,
        present_in={"baseline": False, "test": True, "post_test": False},
        reverted_after_disconnect=attrs.pop("reverted", True),
        attributes=attrs,
    )


def test_default_ruleset_loads():
    rs = RuleSet.default()
    assert rs.version == 1
    assert len(rs.rules) >= 10
    ids = {r.id for r in rs.rules}
    assert "hid-keyboard-appeared-on-connect" in ids


def test_keyboard_finding_is_high():
    rs = RuleSet.default()
    delta = _delta(KIND_INPUT_DEVICE, "input:aaa", ID_INPUT_KEYBOARD="1", label="Evil KB")
    findings = rs.evaluate([delta])
    ids = {f.rule_id for f in findings}
    assert "hid-keyboard-appeared-on-connect" in ids
    kb = next(f for f in findings if f.rule_id == "hid-keyboard-appeared-on-connect")
    assert kb.severity == "high"
    assert kb.related_identities == ["input:aaa"]


def test_network_interface_finding():
    rs = RuleSet.default()
    findings = rs.evaluate([_delta(KIND_NETWORK_INTERFACE, "net:usb0", is_usb=True)])
    assert any(f.rule_id == "network-interface-appeared-on-connect" for f in findings)


def test_persisted_device_flagged():
    rs = RuleSet.default()
    delta = _delta(KIND_USB_DEVICE, "usb:1:2", reverted=False)
    findings = rs.evaluate([delta])
    assert any(f.rule_id == "usb-device-did-not-revert" for f in findings)


def test_persisted_process_not_flagged_as_device():
    # a process still running in post-test is normal, not a "device did not revert"
    rs = RuleSet.default()
    delta = _delta("process", "proc:123:php", reverted=False)
    findings = rs.evaluate([delta])
    assert not any(f.rule_id == "usb-device-did-not-revert" for f in findings)


def test_no_findings_for_baseline_only_change():
    rs = RuleSet.default()
    delta = _delta(KIND_USB_DEVICE, "usb:1:2", change="disappeared", first_seen_phase=None)
    findings = rs.evaluate([delta])
    assert findings == []


def test_findings_sorted_by_severity():
    rs = RuleSet.default()
    delta = _delta(KIND_INPUT_DEVICE, "input:aaa", ID_INPUT_KEYBOARD="1")
    findings = rs.evaluate([delta])
    severities = [f.severity for f in findings]
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    assert severities == sorted(severities, key=lambda s: rank[s], reverse=True)


def test_kernel_ethernet_gadget_is_critical():
    rs = RuleSet.default()
    delta = _delta(
        KIND_KERNEL_MESSAGE,
        "kmsg:cdc_ether # x eth#: register",
        label="cdc_ether 1-1:2.0 usb0: register 'cdc_ether'",
    )
    findings = rs.evaluate([delta])
    assert any(
        f.rule_id == "usb-ethernet-gadget-kernel-signature" and f.severity == "critical"
        for f in findings
    )


def test_block_device_usb_transport():
    rs = RuleSet.default()
    findings = rs.evaluate([_delta(KIND_BLOCK_DEVICE, "block:sda", transport="usb")])
    assert any(f.rule_id == "mass-storage-appeared-on-connect" for f in findings)


def test_custom_ruleset_from_yaml(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "version: 1\n"
        "rules:\n"
        "  - id: only-mice\n"
        "    title: Mouse appeared\n"
        "    severity: low\n"
        "    match:\n"
        "      change: appeared\n"
        "      kind: input_device\n"
        "      attributes:\n"
        "        all:\n"
        "          - {key: capabilities, contains: mouse}\n",
        encoding="utf-8",
    )
    rs = RuleSet.resolve(path)
    assert len(rs.rules) == 1
    hit = rs.evaluate([_delta(KIND_INPUT_DEVICE, "i:1", capabilities=["mouse"])])
    miss = rs.evaluate([_delta(KIND_INPUT_DEVICE, "i:2", capabilities=["keyboard"])])
    assert len(hit) == 1 and miss == []
