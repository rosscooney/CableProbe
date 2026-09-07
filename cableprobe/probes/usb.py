# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""USB device inventory.

Prefers pyudev (rich properties, including HID / interface classes). Falls back
to parsing ``lsusb`` output when pyudev is unavailable.
"""

from __future__ import annotations

import re

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_USB_DEVICE, Observation
from cableprobe.probes.base import (
    Probe,
    ProbeAvailability,
    have_tool,
    run_command,
    udev_context,
)

try:  # pragma: no cover - platform dependent
    import pyudev
except Exception:  # noqa: BLE001
    pyudev = None  # type: ignore[assignment]

log = get_logger("probe.usb")

_LSUSB_LINE = re.compile(
    r"^Bus (?P<bus>\d+) Device (?P<dev>\d+): ID (?P<vid>[0-9a-fA-F]{4}):(?P<pid>[0-9a-fA-F]{4})\s*(?P<name>.*)$"
)

# USB device class codes worth naming in reports.
USB_CLASS_NAMES = {
    "00": "per-interface",
    "02": "communications",
    "03": "hid",
    "06": "image",
    "07": "printer",
    "08": "mass-storage",
    "09": "hub",
    "0a": "cdc-data",
    "0b": "smart-card",
    "0e": "video",
    "01": "audio",
    "ef": "miscellaneous",
    "ff": "vendor-specific",
}


def parse_lsusb(text: str) -> list[Observation]:
    observations: list[Observation] = []
    for line in text.splitlines():
        match = _LSUSB_LINE.match(line.strip())
        if not match:
            continue
        vid = match.group("vid").lower()
        pid = match.group("pid").lower()
        name = (match.group("name") or "").strip()
        identity = f"usb:{vid}:{pid}"
        label = name or f"USB device {vid}:{pid}"
        observations.append(
            Observation(
                kind=KIND_USB_DEVICE,
                identity=identity,
                label=label,
                attributes={
                    "vendor_id": vid,
                    "product_id": pid,
                    "bus": match.group("bus"),
                    "device": match.group("dev"),
                    "description": name,
                    "source": "lsusb",
                },
            )
        )
    return observations


def _interface_classes(id_usb_interfaces: str | None) -> list[str]:
    """``:030101:` -> ['hid'] style decode of ID_USB_INTERFACES."""

    if not id_usb_interfaces:
        return []
    classes: list[str] = []
    for chunk in id_usb_interfaces.strip(":").split(":"):
        if len(chunk) >= 2:
            code = chunk[:2].lower()
            classes.append(USB_CLASS_NAMES.get(code, code))
    return classes


def _observation_from_udev(device) -> Observation:
    vid = (device.get("ID_VENDOR_ID") or "").lower()
    pid = (device.get("ID_MODEL_ID") or "").lower()
    serial = device.get("ID_SERIAL_SHORT")
    identity = f"usb:{vid}:{pid}"
    if serial:
        identity += f":{serial}"

    vendor = device.get("ID_VENDOR_FROM_DATABASE") or device.get("ID_VENDOR")
    model = device.get("ID_MODEL_FROM_DATABASE") or device.get("ID_MODEL")
    label = " ".join(p for p in (vendor, model) if p) or f"USB device {vid}:{pid}"

    interfaces = _interface_classes(device.get("ID_USB_INTERFACES"))
    attrs = {
        "vendor_id": vid,
        "product_id": pid,
        "serial": serial,
        "vendor": vendor,
        "model": model,
        "device_class": device.attributes.asstring("bDeviceClass")
        if hasattr(device, "attributes")
        else None,
        "interface_classes": interfaces,
        "interface_count": len(interfaces),
        "speed": device.attributes.asstring("speed")
        if hasattr(device, "attributes")
        else None,
        "bcd_device": device.get("ID_REVISION"),
        "driver": device.get("ID_USB_DRIVER") or device.driver,
        "devpath": device.get("DEVPATH"),
        "source": "pyudev",
    }
    return Observation(
        kind=KIND_USB_DEVICE,
        identity=identity,
        label=label,
        attributes={k: v for k, v in attrs.items() if v not in (None, "")},
    )


class UsbProbe(Probe):
    name = "usb"
    description = "Inventory of connected USB devices (vendor/model/interface classes)"

    def availability(self) -> ProbeAvailability:
        if pyudev is not None:
            return ProbeAvailability(ok=True, detail="using pyudev")
        if have_tool("lsusb"):
            return ProbeAvailability(ok=True, detail="using lsusb fallback")
        return ProbeAvailability(ok=False, detail="neither pyudev nor lsusb available")

    def snapshot(self) -> list[Observation]:
        if pyudev is not None:
            try:
                context = udev_context()
                observations = []
                for device in context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
                    try:
                        observations.append(_observation_from_udev(device))
                    except Exception as exc:  # noqa: BLE001
                        log.debug("skipping usb device: %s", exc)
                return observations
            except Exception as exc:  # noqa: BLE001  # pragma: no cover
                log.warning("pyudev USB enumeration failed (%s); trying lsusb", exc)

        code, out, err = run_command(["lsusb"])
        if code != 0:
            raise RuntimeError(err.strip() or "lsusb failed")
        return parse_lsusb(out)
