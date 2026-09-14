# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os

import pytest

from cableprobe.fsutil import UnsafePathError
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


def test_udev_event_attributes_are_normalised_for_implant_matching():
    from cableprobe.probes.udev_monitor import _extract_attributes

    class FakeDev:
        subsystem = "usb"

        def get(self, k):
            return {"ID_VENDOR_ID": "16D0", "ID_MODEL_ID": "0753",
                    "ID_SERIAL_SHORT": "X1"}.get(k)

    a = _extract_attributes(FakeDev())
    assert a["vendor_id"] == "16d0" and a["product_id"] == "0753"

    d = _usb_delta("16d0", "0753", identity="usb:1-1.2")
    d.change = "appeared"
    d.transient = True
    assert any(
        f.rule_id == "known-implant-device" for f in ImplantList.load().check([d])
    )


def test_apply_allowlist_noop_when_empty():
    findings = [Finding(rule_id="x", title="x", severity="high")]
    assert apply_allowlist(findings, [], Allowlist([], None)) is findings


def test_allowlisted_device_does_not_downgrade_another_devices_finding():
    # one trusted keyboard, one untrusted - each triggers the same rule
    deltas = [
        _usb_delta("046d", "c31c", "TRUSTED", identity="input:good", kind="input_device"),
        _usb_delta("dead", "beef", "EVIL", identity="input:evil", kind="input_device"),
    ]
    raw = [
        Finding(rule_id="hid-keyboard-appeared-on-connect", title="HID keyboard appeared",
                severity="high", related_identities=["input:good"]),
        Finding(rule_id="hid-keyboard-appeared-on-connect", title="HID keyboard appeared",
                severity="high", related_identities=["input:evil"]),
    ]
    al = Allowlist([], None)
    al.add("046d", "c31c", "TRUSTED", "my Logitech")

    out = apply_allowlist(raw, deltas, al)
    by_id = {f.related_identities[0]: f for f in out}
    assert by_id["input:good"].severity == "info"
    assert by_id["input:evil"].severity == "high"  # untrusted keyboard still loud


# --------------------------------------------------------------------------
# Allowlist trust verification (issue: protect the allowlist from tampering)
# --------------------------------------------------------------------------


def test_allowlist_load_missing_file_is_not_an_error_even_with_trust_check(tmp_path):
    # the common case: no allowlist configured at all
    al = Allowlist.load(tmp_path / "nope.yaml", verify_trust=True, invoking_uid=os.getuid())
    assert len(al) == 0


def test_allowlist_load_safe_file_with_trust_check(tmp_path):
    path = tmp_path / "allow.yaml"
    al = Allowlist.load(path, verify_trust=True, invoking_uid=os.getuid())
    al.add("0bda", "8153", "750998", "Belkin USB-C LAN")
    al.save(invoking_uid=os.getuid())

    reloaded = Allowlist.load(path, verify_trust=True, invoking_uid=os.getuid())
    assert len(reloaded) == 1
    assert reloaded.match("0bda", "8153", "750998").name == "Belkin USB-C LAN"


def test_allowlist_load_rejects_a_symlinked_file_when_trust_checked(tmp_path):
    secret = tmp_path / "secret.yaml"
    secret.write_text("allow: [{vid: dead, pid: beef, name: injected}]")
    link = tmp_path / "allow.yaml"
    link.symlink_to(secret)

    with pytest.raises(UnsafePathError, match="symlink"):
        Allowlist.load(link, verify_trust=True, invoking_uid=os.getuid())

    # without the trust check, the existing symlink-safe read still refuses
    # to follow it (read_text_nofollow) - it degrades to "no allowlist"
    # rather than silently trusting attacker-controlled content
    al = Allowlist.load(link, verify_trust=False)
    assert len(al) == 0


def test_allowlist_load_rejects_a_symlinked_ancestor_directory(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "allow.yaml").write_text("allow: []")
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(real_dir)

    with pytest.raises(UnsafePathError, match="symlink"):
        Allowlist.load(
            linked_dir / "allow.yaml", verify_trust=True, invoking_uid=os.getuid()
        )


def test_allowlist_load_rejects_insecure_permissions(tmp_path):
    path = tmp_path / "allow.yaml"
    path.write_text("allow: []")
    os.chmod(path, 0o666)
    try:
        with pytest.raises(UnsafePathError, match="writable by other users"):
            Allowlist.load(path, verify_trust=True, invoking_uid=os.getuid())
    finally:
        os.chmod(path, 0o644)


def test_allowlist_load_rejects_a_foreign_owned_directory(tmp_path, monkeypatch):
    from cableprobe import knowledge as knowledge_mod

    path = tmp_path / "allow.yaml"
    path.write_text("allow: []")

    monkeypatch.setattr(
        knowledge_mod,
        "verify_directory_chain",
        lambda directory, **kw: [f"{directory} is owned by uid 65534, not root or the invoking user"],
    )
    with pytest.raises(UnsafePathError, match="65534"):
        Allowlist.load(path, verify_trust=True, invoking_uid=os.getuid())


def test_allowlist_load_rejects_a_non_regular_file(tmp_path):
    fifo = tmp_path / "allow.yaml"
    os.mkfifo(fifo)
    with pytest.raises(UnsafePathError, match="not a regular file"):
        Allowlist.load(fifo, verify_trust=True, invoking_uid=os.getuid())


def test_allowlist_load_rejects_oversized_file(tmp_path, monkeypatch):
    from cableprobe import knowledge as knowledge_mod

    path = tmp_path / "allow.yaml"
    path.write_text("allow: []\n# " + "x" * 100)
    monkeypatch.setattr(knowledge_mod, "MAX_ALLOWLIST_BYTES", 10)

    with pytest.raises(UnsafePathError, match="refusing to load"):
        Allowlist.load(path, verify_trust=True, invoking_uid=os.getuid())

    # without the trust check: degrade gracefully rather than crash the run
    al = Allowlist.load(path, verify_trust=False)
    assert len(al) == 0


def test_allowlist_load_rejects_malformed_yaml(tmp_path):
    path = tmp_path / "allow.yaml"
    path.write_text("allow: [this is: not: valid: yaml: [[[")

    with pytest.raises(UnsafePathError, match="malformed"):
        Allowlist.load(path, verify_trust=True, invoking_uid=os.getuid())

    # unprivileged: degrade gracefully instead of crashing the whole run
    al = Allowlist.load(path, verify_trust=False)
    assert len(al) == 0


def test_allowlist_load_malformed_yaml_without_trust_check_does_not_raise(tmp_path):
    # regression: previously yaml.safe_load() was called with no try/except
    # at all, so malformed YAML crashed the CLI outright
    path = tmp_path / "allow.yaml"
    path.write_text(": : :\nnot valid\n  - [")
    al = Allowlist.load(path)
    assert len(al) == 0


def test_allowlist_save_refuses_directory_replaced_after_verification(tmp_path, monkeypatch):
    """Same deterministic TOCTOU simulation as the report-writing tests: the
    directory passes verification, but is swapped for a symlink before the
    real open happens. save() must not write through the swap."""

    from cableprobe import fsutil as fsutil_mod

    target = tmp_path / "sessions"
    target.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    real_verify = fsutil_mod.verify_directory_chain

    def swap_after_check(directory, **kwargs):
        reasons = real_verify(directory, **kwargs)
        target.rmdir()
        target.symlink_to(elsewhere)
        return reasons

    monkeypatch.setattr(fsutil_mod, "verify_directory_chain", swap_after_check)
    al = Allowlist([], target / "allowlist.yaml")
    al.add("dead", "beef", None, "x")
    with pytest.raises(OSError):
        al.save()
    assert list(elsewhere.iterdir()) == []


def test_apply_allowlist_leaves_behavioural_findings_alone():
    deltas = [_usb_delta("046d", "c31c", "S", identity="kbdtiming:event3", kind="keystroke_timing")]
    # a behavioural delta carries no vendor_id -> nothing to allowlist against
    deltas[0].attributes = {}
    findings = [Finding(rule_id="keystroke-injection-cadence", title="Injection cadence",
                        severity="high", related_identities=["kbdtiming:event3"])]
    al = Allowlist([], None)
    al.add("046d", "c31c", "S", "my keyboard")
    assert apply_allowlist(findings, deltas, al)[0].severity == "high"
