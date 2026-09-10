# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Serial / modem (TTY) device inventory.

A CDC-ACM, FTDI or cp210x style USB serial interface that enumerates only while
the unknown cable is connected is a covert command / debug / AT-command channel
-- the "it is also a modem" trick used by several cable implants.

Uses pyudev's ``tty`` subsystem when available, otherwise walks
``/sys/class/tty`` and keeps only the entries backed by a real device (which
excludes the dozens of virtual ``ttyN`` consoles).
"""

from __future__ import annotations

from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_SERIAL_DEVICE, Observation
from cableprobe.probes.base import (
    Probe,
    ProbeAvailability,
    sysfs_device_is_usb,
    sysfs_driver,
    udev_context,
)

try:  # pragma: no cover - platform dependent
    import pyudev
except ImportError:
    pyudev = None  # type: ignore[assignment]

log = get_logger("probe.serial")

SYS_CLASS_TTY = "/sys/class/tty"

#: Kernel driver name substrings that indicate a USB-attached serial port.
_USB_SERIAL_DRIVERS = (
    "cdc_acm",
    "ftdi_sio",
    "cp210x",
    "ch341",
    "pl2303",
    "option",
    "usb_serial",
    "qcserial",
    "cdc-acm",
)


def scan_sysfs_tty(root: str = SYS_CLASS_TTY) -> list[Observation]:
    """Return an Observation for every ``/sys/class/tty`` entry with a real device."""

    base = Path(root)
    if not base.is_dir():
        return []
    observations: list[Observation] = []
    for entry in sorted(base.iterdir()):
        device_link = entry / "device"
        if not device_link.exists():
            # Pure virtual console (tty0..tty63, console, ...) - not interesting.
            continue
        driver = sysfs_driver(entry)
        is_usb = sysfs_device_is_usb(entry)
        name = entry.name
        observations.append(
            Observation(
                kind=KIND_SERIAL_DEVICE,
                identity=f"tty:{name}",
                label=f"serial device /dev/{name}"
                + (f" ({driver})" if driver else ""),
                attributes={
                    "name": name,
                    "devname": f"/dev/{name}",
                    "driver": driver,
                    "is_usb": is_usb,
                    "usb_serial": bool(
                        driver and any(d in driver for d in _USB_SERIAL_DRIVERS)
                    ),
                    "source": "sysfs",
                },
            )
        )
    return observations


def _observation_from_udev(device) -> Observation:
    name = device.sys_name
    devname = device.get("DEVNAME") or f"/dev/{name}"
    driver = device.get("ID_USB_DRIVER") or device.driver
    is_usb = device.get("ID_BUS") == "usb" or (device.get("ID_USB_INTERFACES") is not None)
    return Observation(
        kind=KIND_SERIAL_DEVICE,
        identity=f"tty:{name}",
        label=f"serial device {devname}"
        + (f" ({driver})" if driver else ""),
        attributes={
            "name": name,
            "devname": devname,
            "driver": driver,
            "vendor_id": device.get("ID_VENDOR_ID"),
            "product_id": device.get("ID_MODEL_ID"),
            "serial": device.get("ID_SERIAL_SHORT"),
            "vendor": device.get("ID_VENDOR_FROM_DATABASE") or device.get("ID_VENDOR"),
            "model": device.get("ID_MODEL_FROM_DATABASE") or device.get("ID_MODEL"),
            "is_usb": bool(is_usb),
            "usb_serial": bool(
                driver and any(d in driver for d in _USB_SERIAL_DRIVERS)
            ),
            "source": "pyudev",
        },
    )


class SerialDeviceProbe(Probe):
    name = "serial"
    description = "Inventory of serial / modem (TTY) devices, including USB serial"

    def availability(self) -> ProbeAvailability:
        if pyudev is not None:
            return ProbeAvailability(ok=True, detail="using pyudev")
        if Path(SYS_CLASS_TTY).is_dir():
            return ProbeAvailability(ok=True, detail=f"using {SYS_CLASS_TTY}")
        return ProbeAvailability(ok=False, detail="no pyudev and no /sys/class/tty")

    def snapshot(self) -> list[Observation]:
        if pyudev is not None:
            try:
                context = udev_context()
                out: list[Observation] = []
                for device in context.list_devices(subsystem="tty"):
                    # A real serial port has a backing hardware device; the
                    # virtual consoles (ttyN, subsystem tty) have no parent.
                    if device.parent is None:
                        continue
                    name = device.sys_name
                    if name.startswith("tty") and name[3:].isdigit():
                        continue  # virtual console ttyN
                    out.append(_observation_from_udev(device))
                return out
            except Exception as exc:  # noqa: BLE001  # pragma: no cover
                log.warning("pyudev tty enumeration failed (%s); trying sysfs", exc)
        return scan_sysfs_tty(SYS_CLASS_TTY)
