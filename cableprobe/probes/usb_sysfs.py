# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""USB descriptor and topology probes, both driven from ``/sys/bus/usb/devices``.

sysfs exposes the parsed USB descriptors of every attached device without
needing ``lsusb -v`` or root:

* ``usb_descriptors`` emits one observation per *interface* (class / subclass /
  protocol / endpoint count / bound driver) plus the parent device fingerprint.
  This catches composite implants and "descriptor morphing" (the interface set
  of a device changing while it stays enumerated shows up as appeared /
  disappeared interface deltas).
* ``usb_topology`` emits one observation per hub and a single summary
  observation (hub count / device count / tree depth). A hidden hub inside a
  cable -- the usual way HID + storage + network are stacked behind one
  connector -- changes the summary and adds a hub delta.
"""

from __future__ import annotations

from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import (
    KIND_USB_DESCRIPTOR,
    KIND_USB_INTERFACE,
    KIND_USB_TOPOLOGY,
    Observation,
)
from cableprobe.probes.base import Probe, ProbeAvailability

log = get_logger("probe.usb_sysfs")

SYS_BUS_USB_DEVICES = "/sys/bus/usb/devices"

# bDeviceClass / bInterfaceClass code -> short name (superset of the usb probe's).
USB_CLASS_NAMES = {
    "00": "per-interface",
    "01": "audio",
    "02": "communications",
    "03": "hid",
    "05": "physical",
    "06": "image",
    "07": "printer",
    "08": "mass-storage",
    "09": "hub",
    "0a": "cdc-data",
    "0b": "smart-card",
    "0d": "content-security",
    "0e": "video",
    "0f": "personal-healthcare",
    "10": "audio-video",
    "11": "billboard",
    "dc": "diagnostic",
    "e0": "wireless-controller",
    "ef": "miscellaneous",
    "fe": "application-specific",
    "ff": "vendor-specific",
}


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None


def _class_name(code: str | None) -> str | None:
    if code is None:
        return None
    return USB_CLASS_NAMES.get(code.lower().zfill(2), code.lower().zfill(2))


def _is_device_dir(entry: Path) -> bool:
    # Device dirs: usb1, 1-1, 1-1.4  (interface dirs contain a ':').
    return entry.is_dir() and ":" not in entry.name and (entry / "idVendor").exists()


def _is_root_hub(name: str) -> bool:
    return name.startswith("usb") and name[3:].isdigit()


def _depth(name: str) -> int:
    """Rough tree depth from the sysfs name (``1-1.4.2`` -> 3, ``usb1`` -> 0)."""

    if _is_root_hub(name):
        return 0
    tail = name.split("-", 1)[-1]
    return tail.count(".") + 1


def scan_usb_sysfs(root: str = SYS_BUS_USB_DEVICES) -> list[dict]:
    """Return a list of dicts describing every USB device dir under ``root``."""

    base = Path(root)
    if not base.is_dir():
        return []
    devices: list[dict] = []
    for entry in sorted(base.iterdir()):
        if not _is_device_dir(entry):
            continue
        vid = (_read(entry / "idVendor") or "").lower()
        pid = (_read(entry / "idProduct") or "").lower()
        device_class = _read(entry / "bDeviceClass")
        record: dict = {
            "sysname": entry.name,
            "vendor_id": vid,
            "product_id": pid,
            "manufacturer": _read(entry / "manufacturer"),
            "product": _read(entry / "product"),
            "serial": _read(entry / "serial"),
            "device_class": device_class,
            "device_class_name": _class_name(device_class),
            "num_configurations": _read(entry / "bNumConfigurations"),
            "num_interfaces": _read(entry / "bNumInterfaces"),
            "max_power": _read(entry / "bMaxPower"),
            "speed": _read(entry / "speed"),
            "version": _read(entry / "version"),
            "maxchild": _read(entry / "maxchild"),
            "depth": _depth(entry.name),
            "is_root_hub": _is_root_hub(entry.name),
            "interfaces": [],
        }
        for iface in sorted(entry.iterdir()):
            if not (iface.is_dir() and iface.name.startswith(entry.name + ":")):
                continue
            iclass = _read(iface / "bInterfaceClass")
            driver = None
            drv_link = iface / "driver"
            if drv_link.is_symlink() or drv_link.exists():
                try:
                    driver = drv_link.resolve().name
                except OSError:
                    driver = None
            record["interfaces"].append(
                {
                    "sysname": iface.name,
                    "number": _read(iface / "bInterfaceNumber"),
                    "class": iclass,
                    "class_name": _class_name(iclass),
                    "subclass": _read(iface / "bInterfaceSubClass"),
                    "protocol": _read(iface / "bInterfaceProtocol"),
                    "num_endpoints": _read(iface / "bNumEndpoints"),
                    "endpoint_types": _endpoint_types(iface),
                    "driver": driver,
                }
            )
        devices.append(record)
    return devices


_EP_TYPE = {0: "control", 1: "isochronous", 2: "bulk", 3: "interrupt"}


def _endpoint_types(iface: Path) -> list[str]:
    """Transfer types of an interface's endpoints, from its ``ep_XX`` dirs.

    The low two bits of an endpoint's ``bmAttributes`` are the transfer type.
    """

    types: list[str] = []
    for ep in sorted(iface.iterdir()):
        if not (ep.is_dir() and ep.name.startswith("ep_")):
            continue
        raw = _read(ep / "bmAttributes")
        try:
            types.append(_EP_TYPE.get(int(raw, 16) & 0x03, raw))
        except (TypeError, ValueError):
            continue
    return types


def _device_identity(record: dict) -> str:
    ident = f"{record['vendor_id']}:{record['product_id']}"
    if record.get("serial"):
        ident += f":{record['serial']}"
    else:
        ident += f":{record['sysname']}"
    return ident


def _device_label(record: dict) -> str:
    parts = [p for p in (record.get("manufacturer"), record.get("product")) if p]
    return " ".join(parts) or f"USB device {record['vendor_id']}:{record['product_id']}"


# --------------------------------------------------------------------------
# usb_descriptors
# --------------------------------------------------------------------------


def descriptor_observations(devices: list[dict]) -> list[Observation]:
    observations: list[Observation] = []
    for record in devices:
        if record.get("is_root_hub"):
            continue
        dev_ident = _device_identity(record)
        dev_label = _device_label(record)
        iface_class_names = sorted(
            {i["class_name"] for i in record["interfaces"] if i.get("class_name")}
        )
        try:
            num_configs = int(record.get("num_configurations") or 1)
        except (TypeError, ValueError):
            num_configs = 1

        observations.append(
            Observation(
                kind=KIND_USB_DESCRIPTOR,
                identity=f"usbdesc:{dev_ident}",
                label=f"USB descriptor of {dev_label}",
                attributes={
                    "vendor_id": record["vendor_id"],
                    "product_id": record["product_id"],
                    "serial": record.get("serial"),
                    "num_configurations": record.get("num_configurations"),
                    "multi_config": num_configs > 1,
                    "has_manufacturer_string": bool(record.get("manufacturer")),
                    "has_product_string": bool(record.get("product")),
                    "has_serial_string": bool(record.get("serial")),
                    "interface_classes": iface_class_names,
                    "num_interfaces": record.get("num_interfaces"),
                    "device_class_name": record.get("device_class_name"),
                    "max_power": record.get("max_power"),
                },
            )
        )

        for iface in record["interfaces"]:
            number = iface.get("number") or "?"
            ep_types = iface.get("endpoint_types") or []
            cname = iface.get("class_name")
            hid_with_bulk = cname == "hid" and "bulk" in ep_types
            observations.append(
                Observation(
                    kind=KIND_USB_INTERFACE,
                    identity=f"usbif:{dev_ident}:{number}",
                    label=(
                        f"{cname or 'interface'} interface "
                        f"#{number} of {dev_label}"
                    ),
                    attributes={
                        "device_identity": dev_ident,
                        "device_label": dev_label,
                        "vendor_id": record["vendor_id"],
                        "product_id": record["product_id"],
                        "device_class": record.get("device_class"),
                        "device_class_name": record.get("device_class_name"),
                        "interface_number": number,
                        "interface_class": iface.get("class"),
                        "interface_class_name": cname,
                        "interface_subclass": iface.get("subclass"),
                        "interface_protocol": iface.get("protocol"),
                        "num_endpoints": iface.get("num_endpoints"),
                        "endpoint_types": ep_types,
                        "hid_with_bulk_endpoint": hid_with_bulk,
                        "driver": iface.get("driver"),
                        "device_interface_classes": iface_class_names,
                        "device_num_interfaces": record.get("num_interfaces"),
                        "device_num_configurations": record.get("num_configurations"),
                        "max_power": record.get("max_power"),
                        "speed": record.get("speed"),
                    },
                )
            )
    return observations


class UsbDescriptorProbe(Probe):
    name = "usb_descriptors"
    description = "Per-interface USB descriptor inventory from sysfs (class/driver/endpoints)"
    # Descriptor set is captured at each phase boundary; a mid-phase change still
    # lands in the end snapshot and is corroborated by udev events.
    samples_periodically = False

    def availability(self) -> ProbeAvailability:
        if Path(SYS_BUS_USB_DEVICES).is_dir():
            return ProbeAvailability(ok=True, detail=f"using {SYS_BUS_USB_DEVICES}")
        return ProbeAvailability(ok=False, detail=f"{SYS_BUS_USB_DEVICES} not present")

    def snapshot(self) -> list[Observation]:
        return descriptor_observations(scan_usb_sysfs(SYS_BUS_USB_DEVICES))


# --------------------------------------------------------------------------
# usb_topology
# --------------------------------------------------------------------------


def topology_observations(devices: list[dict]) -> list[Observation]:
    hubs = [
        d
        for d in devices
        if (d.get("device_class_name") == "hub")
        or any(i.get("class_name") == "hub" for i in d["interfaces"])
    ]
    non_root_devices = [d for d in devices if not d.get("is_root_hub")]
    external_hubs = [h for h in hubs if not h.get("is_root_hub")]
    max_depth = max((d["depth"] for d in devices), default=0)

    observations: list[Observation] = [
        Observation(
            kind=KIND_USB_TOPOLOGY,
            identity="usbtopology:summary",
            label=(
                f"USB tree: {len(non_root_devices)} device(s), "
                f"{len(external_hubs)} external hub(s), depth {max_depth}"
            ),
            attributes={
                "device_count": len(non_root_devices),
                "hub_count": len(hubs),
                "external_hub_count": len(external_hubs),
                "root_hub_count": len(hubs) - len(external_hubs),
                "max_depth": max_depth,
            },
        )
    ]
    for hub in external_hubs:
        observations.append(
            Observation(
                kind=KIND_USB_TOPOLOGY,
                identity=f"usbhub:{_device_identity(hub)}",
                label=f"USB hub: {_device_label(hub)}",
                attributes={
                    "vendor_id": hub["vendor_id"],
                    "product_id": hub["product_id"],
                    "ports": hub.get("maxchild"),
                    "depth": hub["depth"],
                    "device_class": hub.get("device_class"),
                    "sysname": hub["sysname"],
                },
            )
        )
    return observations


class UsbTopologyProbe(Probe):
    name = "usb_topology"
    description = "USB hub / port tree summary and per-hub inventory from sysfs"
    samples_periodically = False

    def availability(self) -> ProbeAvailability:
        if Path(SYS_BUS_USB_DEVICES).is_dir():
            return ProbeAvailability(ok=True, detail=f"using {SYS_BUS_USB_DEVICES}")
        return ProbeAvailability(ok=False, detail=f"{SYS_BUS_USB_DEVICES} not present")

    def snapshot(self) -> list[Observation]:
        return topology_observations(scan_usb_sysfs(SYS_BUS_USB_DEVICES))
