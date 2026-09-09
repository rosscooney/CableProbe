# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Continuous udev event monitor.

Runs a background thread reading the netlink udev monitor and records every
device add/remove/change/bind event across all subsystems. This is the primary
"something happened" signal that correlates with the cable being connected.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from cableprobe.logging_config import get_logger
from cableprobe.models import (
    KIND_AUDIO_DEVICE,
    KIND_BLOCK_DEVICE,
    KIND_HID_DEVICE,
    KIND_INPUT_DEVICE,
    KIND_NETWORK_INTERFACE,
    KIND_PCI_DEVICE,
    KIND_SERIAL_DEVICE,
    KIND_USB_DEVICE,
    KIND_USB_PD,
    KIND_VIDEO_DEVICE,
    Observation,
    ProbeEvent,
    utcnow,
)
from cableprobe.probes.base import Probe, ProbeAvailability, udev_context

try:  # pragma: no cover - platform dependent
    import pyudev
except Exception:  # noqa: BLE001
    pyudev = None  # type: ignore[assignment]

log = get_logger("probe.udev")

# Only these udev subsystems are reported. Plugging in one USB device brings up
# a swarm of kernel-internal sysfs objects (scsi_device, scsi_disk, bsg, bdi,
# scsi_generic, ...) that are not devices in any meaningful sense; matching
# events to a known subsystem here filters them out.
_SUBSYSTEM_KIND = {
    "usb": KIND_USB_DEVICE,
    "block": KIND_BLOCK_DEVICE,
    "net": KIND_NETWORK_INTERFACE,
    "input": KIND_INPUT_DEVICE,
    "hidraw": KIND_HID_DEVICE,
    "hid": KIND_HID_DEVICE,
    "tty": KIND_SERIAL_DEVICE,
    "sound": KIND_AUDIO_DEVICE,
    "video4linux": KIND_VIDEO_DEVICE,
    "pci": KIND_PCI_DEVICE,
    "thunderbolt": KIND_PCI_DEVICE,
    "typec": KIND_USB_PD,
    "bluetooth": KIND_USB_DEVICE,
}


def event_is_interesting(subsystem: str | None, devtype: str | None) -> bool:
    """False for subsystems with no probe, and for block partitions (the disk
    they belong to is reported on its own)."""

    if subsystem not in _SUBSYSTEM_KIND:
        return False
    if subsystem == "block" and devtype == "partition":
        return False
    return True

_INTERESTING_ATTR_KEYS = (
    "ID_VENDOR",
    "ID_VENDOR_ID",
    "ID_VENDOR_FROM_DATABASE",
    "ID_MODEL",
    "ID_MODEL_ID",
    "ID_MODEL_FROM_DATABASE",
    "ID_SERIAL",
    "ID_SERIAL_SHORT",
    "ID_USB_INTERFACES",
    "ID_USB_DRIVER",
    "ID_BUS",
    "ID_INPUT",
    "ID_INPUT_KEYBOARD",
    "ID_INPUT_MOUSE",
    "ID_INPUT_TOUCHPAD",
    "ID_INPUT_TABLET",
    "ID_NET_NAME_MAC",
    "ID_NET_DRIVER",
    "INTERFACE",
    "DEVNAME",
    "DEVTYPE",
    "DRIVER",
    "PRODUCT",
    "TYPE",
)


def kind_for_device(subsystem: str | None, devtype: str | None) -> str:
    if subsystem in _SUBSYSTEM_KIND:
        return _SUBSYSTEM_KIND[subsystem]
    if subsystem:
        return f"{subsystem}_device"
    return "unknown_device"


def _device_identity(device) -> str:
    props = device
    vendor = props.get("ID_VENDOR_ID")
    model = props.get("ID_MODEL_ID")
    serial = props.get("ID_SERIAL_SHORT")
    if vendor and model:
        base = f"usb:{vendor}:{model}"
        if serial:
            base += f":{serial}"
        return base
    interface = props.get("INTERFACE")
    if interface:
        return f"net:{interface}"
    devname = props.get("DEVNAME")
    if devname:
        return devname
    return device.sys_path or device.sys_name


def _device_label(device) -> str:
    vendor = device.get("ID_VENDOR_FROM_DATABASE") or device.get("ID_VENDOR")
    model = device.get("ID_MODEL_FROM_DATABASE") or device.get("ID_MODEL")
    parts = [p for p in (vendor, model) if p]
    if parts:
        return " ".join(parts)
    return device.get("DEVNAME") or device.sys_name or (device.subsystem or "device")


def _extract_attributes(device) -> dict[str, object]:
    attrs: dict[str, object] = {}
    for key in _INTERESTING_ATTR_KEYS:
        value = device.get(key)
        if value is not None:
            attrs[key] = value
    if device.subsystem:
        attrs.setdefault("SUBSYSTEM", device.subsystem)
    return attrs


class UdevMonitorProbe(Probe):
    name = "udev_monitor"
    description = "Background monitor of udev device add/remove/change events (all subsystems)"

    #: Cap on buffered events so an event-storming device cannot exhaust memory
    #: while the operator is between phases.
    MAX_BUFFERED_EVENTS = 20000

    def __init__(self, config, session_start: float) -> None:
        super().__init__(config, session_start)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._events: deque[ProbeEvent] = deque(maxlen=self.MAX_BUFFERED_EVENTS)
        self._dropped = 0
        self._monitor = None

    def availability(self) -> ProbeAvailability:
        if pyudev is None:
            return ProbeAvailability(ok=False, detail="pyudev is not installed / importable")
        try:
            udev_context()
        except Exception as exc:  # noqa: BLE001  # pragma: no cover
            return ProbeAvailability(ok=False, detail=f"pyudev.Context() failed: {exc}")
        return ProbeAvailability(ok=True)

    async def start(self) -> None:
        if pyudev is None:
            log.warning("udev monitor unavailable: pyudev not importable")
            return
        try:
            context = udev_context()
            self._monitor = pyudev.Monitor.from_netlink(context)
            self._monitor.start()
        except Exception as exc:  # noqa: BLE001  # pragma: no cover
            log.warning("could not start udev monitor: %s", exc)
            self._monitor = None
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="cableprobe-udev-monitor", daemon=True
        )
        self._thread.start()
        log.debug("udev monitor thread started")

    async def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=3.0)
        self._thread = None
        self._monitor = None

    def _run(self) -> None:  # pragma: no cover - needs real udev
        monitor = self._monitor
        assert monitor is not None
        while not self._stop.is_set():
            try:
                device = monitor.poll(timeout=0.5)
            except Exception as exc:  # noqa: BLE001
                log.debug("udev poll error: %s", exc)
                time.sleep(0.1)  # avoid a hot spin if poll keeps failing
                continue
            if device is None:
                continue
            if not event_is_interesting(device.subsystem, device.get("DEVTYPE")):
                continue
            try:
                event = self._to_event(device)
            except Exception as exc:  # noqa: BLE001
                log.debug("failed to convert udev device: %s", exc)
                continue
            with self._lock:
                if (
                    self._events.maxlen is not None
                    and len(self._events) == self._events.maxlen
                ):
                    self._dropped += 1
                self._events.append(event)

    def _to_event(self, device) -> ProbeEvent:  # pragma: no cover - needs real udev
        return ProbeEvent(
            timestamp=utcnow(),
            probe=self.name,
            action=str(device.action or "unknown"),
            kind=kind_for_device(device.subsystem, device.get("DEVTYPE")),
            identity=_device_identity(device),
            label=_device_label(device),
            attributes=_extract_attributes(device),
        )

    def drain_events(self) -> list[ProbeEvent]:
        with self._lock:
            events = list(self._events)
            self._events.clear()
            dropped = self._dropped
            self._dropped = 0
        if dropped:
            log.warning(
                "udev monitor dropped %d event(s): buffer of %d exceeded "
                "(device may be event-storming)",
                dropped,
                self.MAX_BUFFERED_EVENTS,
            )
        return events

    def snapshot(self) -> list[Observation]:
        # This probe is event-driven; it contributes no snapshot observations.
        return []
