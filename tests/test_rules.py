# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from cableprobe.models import (
    KIND_BLOCK_DEVICE,
    KIND_INPUT_DEVICE,
    KIND_KERNEL_MESSAGE,
    KIND_KERNEL_MODULE,
    KIND_KEYSTROKE_TIMING,
    KIND_MOUNT,
    KIND_NETWORK_CONFIG,
    KIND_NETWORK_INTERFACE,
    KIND_PCI_DEVICE,
    KIND_USB_DEVICE,
    KIND_USB_INTERFACE,
    KIND_USB_PD,
    KIND_WIFI_AP,
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


def test_default_rules_reference_only_known_kinds_and_severities():
    import cableprobe.models as m
    from cableprobe.rules import SEVERITIES, _as_list

    known_kinds = {
        v for k, v in vars(m).items() if k.startswith("KIND_") and isinstance(v, str)
    }
    rs = RuleSet.default()
    seen_ids = set()
    for rule in rs.rules:
        assert rule.id not in seen_ids, f"duplicate rule id {rule.id}"
        seen_ids.add(rule.id)
        assert rule.severity in SEVERITIES, f"{rule.id}: bad severity {rule.severity}"
        for kind in _as_list(rule.match.kind) or []:
            assert kind in known_kinds, f"{rule.id}: unknown kind {kind!r}"
        for phase in _as_list(rule.match.first_seen_phase) or []:
            assert phase in ("baseline", "test", "post_test")
        for change in _as_list(rule.match.change) or []:
            assert change in ("appeared", "disappeared", "modified")


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


def test_hid_interface_descriptor_rule_is_high():
    rs = RuleSet.default()
    delta = _delta(
        KIND_USB_INTERFACE, "usbif:dead:beef:x:00", interface_class_name="hid"
    )
    findings = rs.evaluate([delta])
    hit = next(f for f in findings if f.rule_id == "hid-interface-appeared-on-connect")
    assert hit.severity == "high"


def test_vendor_specific_interface_rule():
    rs = RuleSet.default()
    delta = _delta(
        KIND_USB_INTERFACE, "usbif:1:2:x:01", interface_class_name="vendor-specific"
    )
    findings = rs.evaluate([delta])
    assert any(
        f.rule_id == "vendor-specific-interface-appeared-on-connect" for f in findings
    )


def test_descriptor_morphing_modified_rule():
    rs = RuleSet.default()
    delta = _delta(
        KIND_USB_INTERFACE,
        "usbif:1:2:x:00",
        change="modified",
        device_num_interfaces="3",
    )
    findings = rs.evaluate([delta])
    assert any(f.rule_id == "device-interface-set-changed" for f in findings)


def test_typec_data_role_change_is_high():
    rs = RuleSet.default()
    delta = _delta(
        KIND_USB_PD, "typec:port0", change="modified", data_role="host"
    )
    findings = rs.evaluate([delta])
    hit = next(f for f in findings if f.rule_id == "typec-data-role-changed-on-connect")
    assert hit.severity == "high"


def test_pci_device_appeared_is_critical():
    rs = RuleSet.default()
    findings = rs.evaluate([_delta(KIND_PCI_DEVICE, "pci:0000:00:1c.4")])
    hit = next(f for f in findings if f.rule_id == "pci-device-appeared-on-connect")
    assert hit.severity == "critical"


def test_default_route_change_is_critical():
    rs = RuleSet.default()
    delta = _delta(
        KIND_NETWORK_CONFIG,
        "route:default",
        change="modified",
        label="default route via 169.254.0.1 dev usb0",
    )
    findings = rs.evaluate([delta])
    hit = next(f for f in findings if f.rule_id == "default-route-changed-on-connect")
    assert hit.severity == "critical"


def test_gadget_module_and_generic_module_rules():
    rs = RuleSet.default()
    gadget = _delta(KIND_KERNEL_MODULE, "kmod:rndis_host", label="kernel module rndis_host")
    ids = {f.rule_id for f in rs.evaluate([gadget])}
    assert "gadget-driver-module-loaded-on-connect" in ids
    assert "kernel-module-loaded-on-connect" in ids


def test_removable_mount_rule_is_high():
    rs = RuleSet.default()
    findings = rs.evaluate([_delta(KIND_MOUNT, "mount:/media/pi/USB")])
    hit = next(f for f in findings if f.rule_id == "removable-media-mounted-on-connect")
    assert hit.severity == "high"


def test_strong_wifi_ap_rule_is_high_weak_is_low():
    rs = RuleSet.default()
    strong = _delta(KIND_WIFI_AP, "wifi:aa:bb:cc:dd:ee:ff", strong_signal="True")
    ids = {f.rule_id: f.severity for f in rs.evaluate([strong])}
    assert ids.get("strong-wifi-ap-appeared-on-connect") == "high"
    assert ids.get("wifi-ap-appeared-on-connect") == "low"

    weak = _delta(KIND_WIFI_AP, "wifi:11:22:33:44:55:66", strong_signal="False")
    weak_ids = {f.rule_id for f in rs.evaluate([weak])}
    assert "strong-wifi-ap-appeared-on-connect" not in weak_ids
    assert "wifi-ap-appeared-on-connect" in weak_ids


def test_keystroke_injection_is_critical():
    rs = RuleSet.default()
    injected = _delta(
        KIND_KEYSTROKE_TIMING, "kbdtiming:event3", looks_injected="True"
    )
    findings = {f.rule_id: f.severity for f in rs.evaluate([injected])}
    assert findings.get("keystroke-injection-detected") == "critical"
    assert findings.get("keystrokes-during-test-phase") == "medium"

    # typing at human speed during the test phase is still medium, not critical
    human = _delta(KIND_KEYSTROKE_TIMING, "kbdtiming:event3", looks_injected="False")
    human_ids = {f.rule_id for f in rs.evaluate([human])}
    assert "keystroke-injection-detected" not in human_ids
    assert "keystrokes-during-test-phase" in human_ids


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
