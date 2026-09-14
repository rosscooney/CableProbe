# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Parse HID report descriptors, not just interface classes.

``usb_descriptors`` sees "this interface is class HID". This probe reads the
actual *report descriptor* - the structure that tells the host what the device
can send - and flags:

* a device whose descriptor can send **keystrokes** but which did not register
  as a keyboard (a way to inject input while looking like something innocuous);
* a device that mixes a standard input capability with a **vendor-defined**
  usage page (a common covert-channel construction).

Reads the binary descriptors under ``/sys/bus/hid/devices/*/report_descriptor``
(no debugfs, no root needed).
"""

from __future__ import annotations

from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_HID_REPORT, Observation
from cableprobe.probes.base import Probe, ProbeAvailability, read_sysfs

log = get_logger("probe.hid_report")

SYS_BUS_HID_DEVICES = "/sys/bus/hid/devices"

# HID usage pages / usages we care about.
_PAGE_GENERIC_DESKTOP = 0x01
_PAGE_KEYBOARD = 0x07
_PAGE_BUTTON = 0x09
_PAGE_CONSUMER = 0x0C
_GD_POINTER = 0x01
_GD_MOUSE = 0x02
_GD_KEYBOARD = 0x06
_GD_KEYPAD = 0x07


#: HID short-item prefix byte reserved to mean "this is a long item instead"
#: (HID 1.11 sec 6.2.2.3): bSize=10, bType=11, bTag=1111 - a combination no
#: short item ever legitimately uses.
_LONG_ITEM_PREFIX = 0xFE


def parse_hid_report_descriptor(data: bytes) -> dict:
    """Decode a raw HID report descriptor into a capability summary."""

    pages: set[int] = set()
    usages: list[tuple[int | None, int]] = []
    page: int | None = None
    has_output = False
    has_input = False
    long_item_count = 0

    i = 0
    n = len(data)
    while i < n:
        prefix = data[i]
        i += 1

        if prefix == _LONG_ITEM_PREFIX:
            # Long item: prefix, then a 1-byte data length, then a 1-byte
            # long item tag, then that many bytes of data - a completely
            # different layout from the short-item bSize/bType/bTag encoding
            # below. Decoding it as a short item (the previous behaviour)
            # reads the wrong bytes as a "value" and desyncs every item after
            # it for the rest of the descriptor. Long items are essentially
            # unused by real hardware, but that makes them exactly the kind
            # of adversarial construction this parser exists to not be fooled
            # by: a device could plant one to hide a keyboard/pointer usage
            # declaration inside what would then be misread as garbage.
            long_item_count += 1
            if i >= n:
                break  # truncated long-item header - nothing left to parse safely
            long_data_size = data[i]
            i += 1  # the data-size byte just read
            i += 1  # the long item tag byte (no long-item tag matters here)
            i += long_data_size  # skip the item's data payload
            continue

        size = prefix & 0x03
        size = 4 if size == 3 else size
        value = int.from_bytes(data[i : i + size], "little") if size else 0
        i += size
        item_type = (prefix >> 2) & 0x03
        tag = (prefix >> 4) & 0x0F

        if item_type == 1 and tag == 0x0:  # Global: Usage Page
            page = value
            pages.add(value)
        elif item_type == 2 and tag == 0x0:  # Local: Usage
            usages.append((page, value))
        elif item_type == 0 and tag == 0x8:  # Main: Input
            has_input = True
        elif item_type == 0 and tag == 0x9:  # Main: Output
            has_output = True

    has_keyboard = _PAGE_KEYBOARD in pages or any(
        p == _PAGE_GENERIC_DESKTOP and u in (_GD_KEYBOARD, _GD_KEYPAD) for p, u in usages
    )
    has_pointer = _PAGE_BUTTON in pages or any(
        p == _PAGE_GENERIC_DESKTOP and u in (_GD_MOUSE, _GD_POINTER) for p, u in usages
    )
    vendor_pages = sorted(p for p in pages if 0xFF00 <= p <= 0xFFFF)

    return {
        "usage_pages": sorted(pages),
        "has_keyboard_usage": has_keyboard,
        "has_pointer_usage": has_pointer,
        "has_consumer_usage": _PAGE_CONSUMER in pages,
        "has_vendor_usage_page": bool(vendor_pages),
        "vendor_usage_pages": [f"0x{p:04x}" for p in vendor_pages],
        "has_input_report": has_input,
        "has_output_report": has_output,
        "descriptor_bytes": n,
        # real hardware essentially never uses HID long items; a descriptor
        # that does is itself worth a human glance
        "has_long_items": long_item_count > 0,
        "long_item_count": long_item_count,
    }


def _declared_kind(sys_dir: Path) -> str:
    """boot-protocol / driver hint for what the device claims to be."""

    name = (
        read_sysfs(sys_dir / "device" / "name")
        or read_sysfs(sys_dir / "name")
        or ""
    ).lower()
    if "keyboard" in name:
        return "keyboard"
    if "mouse" in name or "pointer" in name or "trackpad" in name:
        return "pointer"
    return "other"


def scan_hid_reports(root: str = SYS_BUS_HID_DEVICES) -> list[Observation]:
    base = Path(root)
    if not base.is_dir():
        return []
    observations: list[Observation] = []
    for entry in sorted(base.iterdir()):
        rdesc = entry / "report_descriptor"
        try:
            data = rdesc.read_bytes()
        except OSError:
            continue
        summary = parse_hid_report_descriptor(data)
        declared = _declared_kind(entry)
        # the sysfs name is <bus>:<VID>:<PID>.<n>
        parts = entry.name.replace(":", ".").split(".")
        vid = parts[1].lower() if len(parts) > 1 else ""
        pid = parts[2].lower() if len(parts) > 2 else ""
        summary["declared"] = declared
        summary["vendor_id"] = vid
        summary["product_id"] = pid
        summary["keyboard_capable_but_not_labelled"] = bool(
            summary["has_keyboard_usage"] and declared != "keyboard"
        )
        summary["vendor_page_with_input"] = bool(
            summary["has_vendor_usage_page"]
            and (summary["has_keyboard_usage"] or summary["has_pointer_usage"])
        )
        observations.append(
            Observation(
                kind=KIND_HID_REPORT,
                identity=f"hidreport:{entry.name}",
                label=(
                    f"HID report descriptor {entry.name} "
                    f"(declared: {declared}"
                    + (", KEYBOARD-CAPABLE" if summary["keyboard_capable_but_not_labelled"] else "")
                    + ")"
                ),
                attributes=summary,
            )
        )
    return observations


class HidReportProbe(Probe):
    name = "hid_report"
    description = "Parses HID report descriptors - catches injection capability the class hides"

    def availability(self) -> ProbeAvailability:
        if Path(SYS_BUS_HID_DEVICES).is_dir():
            return ProbeAvailability(ok=True, detail=f"using {SYS_BUS_HID_DEVICES}")
        return ProbeAvailability(ok=False, detail=f"{SYS_BUS_HID_DEVICES} not present")

    def snapshot(self) -> list[Observation]:
        return scan_hid_reports(SYS_BUS_HID_DEVICES)
