# Copyright (c) 2026-present Stable State Consulting Ltd
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


def test_rule_with_invalid_severity_is_rejected():
    import pytest

    with pytest.raises(Exception):  # pydantic ValidationError
        RuleSet.from_dict(
            {"rules": [{"id": "x", "title": "X", "severity": "critcal"}]}
        )


def test_rule_with_invalid_regex_is_rejected_at_load():
    import pytest

    with pytest.raises(Exception):
        RuleSet.from_dict(
            {"rules": [{"id": "x", "title": "X", "match": {"label_regex": "["}}]}
        )
    with pytest.raises(Exception):
        RuleSet.from_dict(
            {"rules": [{"id": "x", "title": "X",
                        "match": {"attributes": {"all": [{"key": "k", "regex": "("}]}}}]}
        )


def test_one_raising_rule_does_not_sink_the_analysis(monkeypatch):
    from cableprobe.rules import Rule

    rs = RuleSet.default()
    real_check = Rule.check

    def _check(self, delta):
        if self.id == "hid-keyboard-appeared-on-connect":
            raise RuntimeError("boom")
        return real_check(self, delta)

    monkeypatch.setattr(Rule, "check", _check)
    # other rules still run; no exception propagates
    findings = rs.evaluate_raw([_delta(KIND_NETWORK_INTERFACE, "net:usb0", is_usb=True)])
    assert any(f.rule_id == "network-interface-appeared-on-connect" for f in findings)


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
    # a keyboard must NOT also trip the generic HID rule (it has its own)
    assert "hid-generic-appeared-on-connect" not in ids


def test_generic_hid_rule_fires_for_non_keyboard_collection():
    rs = RuleSet.default()
    # e.g. a keyboard's consumer-control collection: HID, but not keyboard/pointer
    delta = _delta(
        KIND_INPUT_DEVICE, "input:cc", capabilities=[], label="Consumer Control"
    )
    ids = {f.rule_id for f in rs.evaluate([delta])}
    assert "hid-generic-appeared-on-connect" in ids
    assert "hid-keyboard-appeared-on-connect" not in ids

    # but a device whose capabilities list says "keyboard" is excluded
    kb_caps = _delta(KIND_INPUT_DEVICE, "input:k", capabilities=["keyboard"])
    kb_ids = {f.rule_id for f in rs.evaluate([kb_caps])}
    assert "hid-generic-appeared-on-connect" not in kb_ids
    assert "hid-keyboard-appeared-on-connect" in kb_ids


def test_not_contains_condition():
    from cableprobe.rules import AttributeCondition

    c = AttributeCondition(key="capabilities", not_contains="keyboard")
    assert c.evaluate({"capabilities": ["mouse", "touchpad"]}) is True
    assert c.evaluate({"capabilities": ["keyboard"]}) is False
    assert c.evaluate({}) is True  # absent key -> passes


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


def test_listener_rules_separate_fixed_and_ephemeral_ports():
    rs = RuleSet.default()

    def _ids(**attrs):
        d = _delta("listening_socket", "listen:tcp:0.0.0.0:x", **attrs)
        return {f.rule_id for f in rs.evaluate([d])}

    assert "new-listener-on-connect" in _ids(port=4444, ephemeral_port=False)
    assert "new-ephemeral-listener-on-connect" in _ids(port=51000, ephemeral_port=True)
    assert "new-listener-on-connect" not in _ids(port=51000, ephemeral_port=True)


def test_transient_device_rule_is_restricted_to_real_device_kinds():
    rs = RuleSet.default()

    def _transient(kind, identity):
        return Delta(
            change="appeared",
            kind=kind,
            identity=identity,
            label=f"{kind} {identity}",
            first_seen_phase="test",
            present_in={"baseline": False, "test": False, "post_test": False},
            transient=True,
        )

    ids = {f.rule_id for f in rs.evaluate([_transient(KIND_USB_DEVICE, "usb:1-2")])}
    assert "transient-device-during-test" in ids

    # udev-worker churn, a flickering listener, a kernel log line - none of
    # these are a device enumerating, so none should trip the rule
    for kind, identity in (
        ("process", "proc:1:udev-worker"),
        ("listening_socket", "listen:tcp:0.0.0.0:1"),
        (KIND_KERNEL_MESSAGE, "kmsg:1"),
    ):
        ids = {f.rule_id for f in rs.evaluate([_transient(kind, identity)])}
        assert "transient-device-during-test" not in ids


def test_repeated_connection_rule_needs_the_repeated_flag():
    rs = RuleSet.default()

    def _ids(**attrs):
        d = _delta("connection_frequency", "conn:freq:tcp:1.2.3.4:443", **attrs)
        return {f.rule_id for f in rs.evaluate([d])}

    assert "repeated-outbound-connection-during-test" in _ids(
        remote="1.2.3.4:443", seen_count=5, sample_count=5, repeated=True
    )
    # a single glimpse (repeated=False) is not a beaconing pattern
    assert "repeated-outbound-connection-during-test" not in _ids(
        remote="1.2.3.4:443", seen_count=1, sample_count=5, repeated=False
    )


def test_power_waveform_rules_fire_on_a_series_delta():
    rs = RuleSet.default()

    def _ids(identity, phase, **attrs):
        d = _delta("power_series", identity, first_seen_phase=phase, **attrs)
        return {f.rule_id for f in rs.evaluate([d])}

    assert "power-current-spiked-during-test" in _ids(
        "power:series:test", "test", current_spike=True
    )
    assert "power-current-spiked-during-test" in _ids(
        "power:series:test", "test", current_spike=False, sustained_excess=True
    )
    # no spike attributes -> the test-phase rule does not fire
    assert "power-current-spiked-during-test" not in _ids(
        "power:series:test", "test", current_spike=False, sustained_excess=False
    )
    assert "power-waveform-excursion-after-disconnect" in _ids(
        "power:series:post_test", "post_test", voltage_excursion=True
    )


def test_persistence_rules_cover_post_test_deletion_and_unreadable():
    rs = RuleSet.default()

    def _ids(delta):
        return {f.rule_id for f in rs.evaluate([delta])}

    # modified only in post-test (after disconnect)
    assert "persistence-point-changed-during-session" in _ids(
        _delta("persistence_item", "persist:/etc/ld.so.preload",
               change="modified", first_seen_phase="post_test")
    )
    # deleted during the session (disappeared -> first_seen_phase None)
    assert "persistence-point-removed-during-session" in _ids(
        _delta("persistence_item", "persist:/etc/udev/rules.d/10-x.rules",
               change="disappeared", first_seen_phase=None)
    )
    # turned into a symlink / FIFO mid-session
    assert "persistence-item-became-unreadable" in _ids(
        _delta("persistence_item", "persist:/root/.ssh/authorized_keys",
               change="modified", fingerprint_incomplete=True)
    )


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


def test_rndis_kernel_line_is_high_plain_cdc_is_not():
    rs = RuleSet.default()
    rndis = _delta(
        KIND_KERNEL_MESSAGE,
        "kmsg:rndis register",
        label="rndis_host 1-1:2.0 usb0: register 'rndis_host'",
    )
    hit = next(
        f for f in rs.evaluate([rndis]) if f.rule_id == "rndis-gadget-kernel-signature"
    )
    assert hit.severity == "high"

    # a normal CDC ethernet line no longer spawns its own finding
    cdc = _delta(
        KIND_KERNEL_MESSAGE, "kmsg:cdc_ether register", label="cdc_ether usb0: register"
    )
    assert not any(
        f.rule_id.endswith("gadget-kernel-signature") for f in rs.evaluate([cdc])
    )


def test_kernel_message_finding_omits_revert_line():
    rs = RuleSet.default()
    delta = _delta(
        KIND_KERNEL_MESSAGE,
        "kmsg:over-current",
        label="usb usb1-port1: over-current change #1",
        reverted=False,
    )
    (finding,) = [
        f for f in rs.evaluate([delta]) if f.rule_id == "kernel-enumeration-errors"
    ]
    assert not any("revert" in line.lower() for line in finding.evidence)


def test_findings_consolidate_by_rule():
    rs = RuleSet.default()
    lines = [
        _delta(KIND_KERNEL_MESSAGE, f"kmsg:rndis line {i}", label=f"rndis line {i}")
        for i in range(5)
    ]
    findings = rs.evaluate(lines)
    rndis = [f for f in findings if f.rule_id == "rndis-gadget-kernel-signature"]
    assert len(rndis) == 1
    assert rndis[0].evidence[0] == "matched 5 times:"
    assert len(rndis[0].related_identities) == 5


def test_block_device_usb_transport():
    rs = RuleSet.default()
    ids = {
        f.rule_id
        for f in rs.evaluate([_delta(KIND_BLOCK_DEVICE, "block:sda", transport="usb")])
    }
    assert "mass-storage-appeared-on-connect" in ids
    # confirmed-USB disk must NOT also trip the generic MEDIUM rule
    assert "mass-storage-appeared-generic" not in ids


def test_block_device_unconfirmed_transport_is_medium_only():
    rs = RuleSet.default()
    ids = {
        f.rule_id
        for f in rs.evaluate(
            [_delta(KIND_BLOCK_DEVICE, "block:xvda", transport=None)]
        )
    }
    assert ids == {"mass-storage-appeared-generic"}


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


def test_gadget_module_rule_fires_for_network_not_storage():
    rs = RuleSet.default()
    net = _delta(KIND_KERNEL_MODULE, "kmod:rndis_host", label="kernel module rndis_host")
    assert any(
        f.rule_id == "gadget-driver-module-loaded-on-connect"
        for f in rs.evaluate([net])
    )
    # a USB disk loading usb_storage / sg / uas is expected - no finding
    for mod in ("usb_storage", "sg", "uas"):
        storage = _delta(KIND_KERNEL_MODULE, f"kmod:{mod}", label=f"kernel module {mod}")
        assert rs.evaluate([storage]) == []


def test_removable_mount_rule_is_high():
    rs = RuleSet.default()
    findings = rs.evaluate([_delta(KIND_MOUNT, "mount:/media/pi/USB")])
    hit = next(f for f in findings if f.rule_id == "removable-media-mounted-on-connect")
    assert hit.severity == "high"


def test_wifi_ap_rule_needs_strong_reverted_and_new_vendor():
    rs = RuleSet.default()

    hit = _delta(
        KIND_WIFI_AP,
        "wifi:aa:bb:cc:dd:ee:ff",
        strong_signal="True",
        reverted=True,
        family_new_this_session="True",
    )
    ids = {f.rule_id: f.severity for f in rs.evaluate([hit])}
    assert ids.get("strong-wifi-ap-appeared-and-reverted") == "high"

    # a rotating BSSID of an AP whose vendor was already at baseline -> no finding
    known_vendor = _delta(
        KIND_WIFI_AP,
        "wifi:be:30:d9:a5:dc:eb",
        strong_signal="True",
        reverted=True,
        family_new_this_session="False",
    )
    assert rs.evaluate([known_vendor]) == []

    # strong + new vendor but still there after disconnect -> no finding
    stayed = _delta(
        KIND_WIFI_AP,
        "wifi:11:22:33:44:55:66",
        strong_signal="True",
        reverted=False,
        family_new_this_session="True",
    )
    assert rs.evaluate([stayed]) == []

    # weak -> no finding (the "any new AP" catch-all is gone)
    assert rs.evaluate([_delta(KIND_WIFI_AP, "wifi:9:9:9:9:9:9", strong_signal="False")]) == []


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
