# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""hid_report / persistence / connections probes."""

from __future__ import annotations

from cableprobe.models import (
    KIND_HID_REPORT,
    KIND_OUTBOUND_CONNECTION,
    KIND_PERSISTENCE_ITEM,
)
from cableprobe.probes.connections import parse_outbound
from cableprobe.probes.hid_report import parse_hid_report_descriptor, scan_hid_reports
from cableprobe.probes.persistence import scan_persistence


# --------------------------------------------------------------------------
# hid_report
# --------------------------------------------------------------------------

# A minimal boot keyboard report descriptor (Usage Page Generic Desktop,
# Usage Keyboard, Collection ...). Enough bytes for the parser.
_KEYBOARD_RDESC = bytes(
    [
        0x05, 0x01,  # Usage Page (Generic Desktop)
        0x09, 0x06,  # Usage (Keyboard)
        0xA1, 0x01,  # Collection (Application)
        0x05, 0x07,  # Usage Page (Keyboard)
        0x81, 0x02,  # Input (Data,Var,Abs)
        0xC0,        # End Collection
    ]
)

_MOUSE_RDESC = bytes(
    [
        0x05, 0x01,  # Usage Page (Generic Desktop)
        0x09, 0x02,  # Usage (Mouse)
        0xA1, 0x01,  # Collection (Application)
        0x09, 0x01,  # Usage (Pointer)
        0x05, 0x09,  # Usage Page (Button)
        0x81, 0x02,  # Input
        0xC0,
    ]
)

_VENDOR_KBD_RDESC = _KEYBOARD_RDESC + bytes([0x06, 0x00, 0xFF, 0x09, 0x01, 0x81, 0x02])


def test_parse_keyboard_descriptor():
    s = parse_hid_report_descriptor(_KEYBOARD_RDESC)
    assert s["has_keyboard_usage"] is True
    assert s["has_pointer_usage"] is False
    assert s["has_vendor_usage_page"] is False


def test_parse_mouse_descriptor():
    s = parse_hid_report_descriptor(_MOUSE_RDESC)
    assert s["has_keyboard_usage"] is False
    assert s["has_pointer_usage"] is True


def test_parse_vendor_page_with_keyboard():
    s = parse_hid_report_descriptor(_VENDOR_KBD_RDESC)
    assert s["has_keyboard_usage"] is True
    assert s["has_vendor_usage_page"] is True
    assert "0xff00" in s["vendor_usage_pages"]


def test_scan_hid_reports_flags_unlabelled_keyboard(tmp_path):
    d = tmp_path / "0003:04F2:0939.0005"
    d.mkdir()
    (d / "report_descriptor").write_bytes(_KEYBOARD_RDESC)
    (d / "name").write_text("PixArt USB Optical Mouse", encoding="utf-8")

    out = scan_hid_reports(str(tmp_path))
    assert len(out) == 1
    o = out[0]
    assert o.kind == KIND_HID_REPORT
    assert o.attributes["declared"] == "pointer"
    assert o.attributes["keyboard_capable_but_not_labelled"] is True
    assert o.attributes["vendor_id"] == "04f2"


def test_scan_hid_reports_ok_for_real_keyboard(tmp_path):
    d = tmp_path / "0003:046D:C31C.0001"
    d.mkdir()
    (d / "report_descriptor").write_bytes(_KEYBOARD_RDESC)
    (d / "name").write_text("Logitech USB Keyboard", encoding="utf-8")
    (o,) = scan_hid_reports(str(tmp_path))
    assert o.attributes["keyboard_capable_but_not_labelled"] is False


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------


def test_scan_persistence_hashes_targets(tmp_path):
    rules = tmp_path / "udev"
    rules.mkdir()
    (rules / "99-evil.rules").write_text('ACTION=="add", RUN+="/tmp/x"\n', encoding="utf-8")
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    out = scan_persistence(
        targets=[("udev-rule", str(rules / "*.rules")), ("hosts", str(hosts))],
        home_roots=(),
    )
    ids = {o.identity for o in out}
    assert f"persist:{rules / '99-evil.rules'}" in ids
    item = next(o for o in out if o.identity.endswith("99-evil.rules"))
    assert item.kind == KIND_PERSISTENCE_ITEM
    assert item.attributes["sha256_16"] and item.attributes["present"] is True

    # a byte change moves the hash -> a delta later
    before = item.attributes["sha256_16"]
    (rules / "99-evil.rules").write_text("changed\n", encoding="utf-8")
    after = next(
        o
        for o in scan_persistence(
            targets=[("udev-rule", str(rules / "*.rules"))], home_roots=()
        )
    ).attributes["sha256_16"]
    assert before != after


# --------------------------------------------------------------------------
# connections
# --------------------------------------------------------------------------

_PROC_NET_TCP = """\
  sl  local_address rem_address   st ... uid ... inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 1 0000
   1: 0100007F:8AE2 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000 0 2 0000
   2: 0100007F:9002 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000 0 3 0000
   3: 0A00020F:C1B4 22D8B85D:01BB 02 00000000:00000000 00:00000000 00000000     0 0 4 0000
"""


def test_parse_outbound_keeps_only_routable_active():
    out = parse_outbound(_PROC_NET_TCP)
    remotes = sorted(o.attributes["remote"] for o in out)
    # 8.8.8.8:443 (established) and 93.184.216.34:443 (syn_sent) kept;
    # the LISTEN socket and the loopback->loopback connection dropped
    assert remotes == ["8.8.8.8:443", "93.184.216.34:443"]
    assert all(o.kind == KIND_OUTBOUND_CONNECTION for o in out)
