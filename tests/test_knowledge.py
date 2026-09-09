# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from cableprobe.knowledge import (
    Allowlist,
    ImplantList,
    apply_allowlist,
)
from cableprobe.models import Delta, Finding


def _usb_delta(vid, pid, serial=None, identity=None, kind="usb_device"):
    return Delta(
        change="appeared",
        kind=kind,
        identity=identity or f"usb:{vid}:{pid}",
        label=f"device {vid}:{pid}",
        first_seen_phase="test",
        present_in={"baseline": False, "test": True, "post_test": False},
        attributes={"vendor_id": vid, "product_id": pid, "serial": serial},
    )


# --------------------------------------------------------------------------
# ImplantList
# --------------------------------------------------------------------------


def test_packaged_implant_list_loads():
    il = ImplantList.load()
    assert len(il) >= 10
    assert il.match("16d0", "0753") is not None  # Digispark


def test_implant_match_normalises_hex():
    il = ImplantList.load()
    assert il.match("0x16D0", "753") is il.match("16d0", "0753")


def test_implant_check_flags_once_per_id():
    il = ImplantList.load()
    deltas = [
        _usb_delta("16d0", "0753", identity="a"),
        _usb_delta("16d0", "0753", identity="b"),  # same id, second interface
        _usb_delta("dead", "beef", identity="c"),  # not on the list
    ]
    findings = il.check(deltas)
    assert len(findings) == 1
    assert findings[0].rule_id == "known-implant-device"
    assert findings[0].severity == "high"


def test_extra_implants_file_is_merged(tmp_path):
    extra = tmp_path / "mine.yaml"
    extra.write_text(
        "implants:\n  - {vid: dead, pid: beef, name: My Test Implant, severity: critical}\n",
        encoding="utf-8",
    )
    il = ImplantList.load(extra)
    entry = il.match("dead", "beef")
    assert entry is not None and entry.severity == "critical"


# --------------------------------------------------------------------------
# Allowlist
# --------------------------------------------------------------------------


def test_allowlist_roundtrip(tmp_path):
    path = tmp_path / "allow.yaml"
    al = Allowlist.load(path)
    assert len(al) == 0
    al.add("0bda", "8153", "750998", "Belkin USB-C LAN")
    al.add("046d", "c52b", None, "Logitech receiver")
    al.save()

    reloaded = Allowlist.load(path)
    assert len(reloaded) == 2
    assert reloaded.match("0bda", "8153", "750998").name == "Belkin USB-C LAN"
    assert reloaded.match("0bda", "8153", "other") is None  # serial must match
    assert reloaded.match("046d", "c52b", "anything").name == "Logitech receiver"


def test_allowlist_add_replaces_duplicate(tmp_path):
    al = Allowlist.load(tmp_path / "a.yaml")
    al.add("1", "2", "s", "first")
    al.add("1", "2", "s", "second")
    assert len(al) == 1 and al.entries[0].name == "second"


def test_apply_allowlist_downgrades_matching_findings():
    deltas = [_usb_delta("0bda", "8153", "750998", identity="net-dev")]
    findings = [
        Finding(
            rule_id="network-interface-appeared-on-connect",
            title="Network interface appeared",
            severity="high",
            related_identities=["net-dev"],
        ),
        Finding(
            rule_id="default-route-changed-on-connect",
            title="Default route changed",
            severity="critical",
            related_identities=["route:default"],  # not the allowlisted device
        ),
    ]
    al = Allowlist([], None)
    al.add("0bda", "8153", "750998", "Belkin USB-C LAN")

    out = apply_allowlist(findings, deltas, al)
    net = next(f for f in out if f.rule_id == "network-interface-appeared-on-connect")
    route = next(f for f in out if f.rule_id == "default-route-changed-on-connect")
    assert net.severity == "info"
    assert "allowlisted: Belkin USB-C LAN" in net.title
    assert route.severity == "critical"  # unrelated finding untouched


def test_apply_allowlist_noop_when_empty():
    findings = [Finding(rule_id="x", title="x", severity="high")]
    assert apply_allowlist(findings, [], Allowlist([], None)) is findings
