# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Host-state probes that give a cable implant away indirectly.

* ``kernel_modules`` -- ``/proc/modules``. A driver auto-loading on connect
  (``rndis_host``, ``cdc_ncm``, ``usb_storage``, ``uas``, ``usbserial`` ...) is
  a one-line tell, and complements the raw kernel log.
* ``mounts`` -- filesystem mounts backed by a real device or under a removable
  media path. Answers "did the storage get **mounted**", which the ``block``
  probe (which only sees the device) cannot.
* ``pci`` -- ``/sys/bus/pci/devices`` and ``/sys/bus/thunderbolt/devices``. A
  USB4 / Thunderbolt cable that tunnels PCIe brings up a new PCI device and a
  DMA-capable attack surface.
"""

from __future__ import annotations

from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import (
    KIND_KERNEL_MODULE,
    KIND_MOUNT,
    KIND_PCI_DEVICE,
    Observation,
)
from cableprobe.probes.base import Probe, ProbeAvailability

log = get_logger("probe.system_state")

PROC_MODULES = "/proc/modules"
PROC_MOUNTS = "/proc/mounts"
SYS_BUS_PCI = "/sys/bus/pci/devices"
SYS_BUS_THUNDERBOLT = "/sys/bus/thunderbolt/devices"

#: Mount points under these roots are operator-visible removable media.
_REMOVABLE_MOUNT_ROOTS = ("/media", "/mnt", "/run/media")


# --------------------------------------------------------------------------
# kernel modules
# --------------------------------------------------------------------------


def parse_proc_modules(text: str) -> list[Observation]:
    """Parse ``/proc/modules`` into one observation per loaded module."""

    observations: list[Observation] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name, size, refcount, deps = parts[0], parts[1], parts[2], parts[3]
        state = parts[4] if len(parts) > 4 else None
        used_by = [d for d in deps.rstrip(",").split(",") if d and d != "-"]
        observations.append(
            Observation(
                kind=KIND_KERNEL_MODULE,
                identity=f"kmod:{name}",
                label=f"kernel module {name}",
                attributes={
                    "name": name,
                    "size": _int(size),
                    "refcount": _int(refcount),
                    "used_by": used_by,
                    "state": state,
                },
            )
        )
    return observations


def _int(value: str) -> int | str:
    try:
        return int(value)
    except ValueError:
        return value


class KernelModuleProbe(Probe):
    name = "kernel_modules"
    description = "Loaded kernel modules (/proc/modules); catches drivers loaded on connect"
    # ~150 modules on a typical host; a driver loaded because of the cable is
    # still present in the phase end snapshot (which is what analysis compares),
    # so there is no need to copy the full list into every periodic sample.
    samples_periodically = False

    def availability(self) -> ProbeAvailability:
        if Path(PROC_MODULES).exists():
            return ProbeAvailability(ok=True)
        return ProbeAvailability(ok=False, detail=f"{PROC_MODULES} not present")

    def snapshot(self) -> list[Observation]:
        path = Path(PROC_MODULES)
        if not path.exists():
            raise RuntimeError(f"{PROC_MODULES} not present")
        return parse_proc_modules(path.read_text(encoding="utf-8", errors="ignore"))


# --------------------------------------------------------------------------
# mounts
# --------------------------------------------------------------------------


def parse_proc_mounts(text: str) -> list[Observation]:
    """Parse ``/proc/mounts``, keeping device-backed and removable-media mounts."""

    observations: list[Observation] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        source, target, fstype, options = parts[0], parts[1], parts[2], parts[3]
        target = target.replace("\\040", " ")
        device_backed = source.startswith("/dev/")
        removable = any(
            target == root or target.startswith(root + "/")
            for root in _REMOVABLE_MOUNT_ROOTS
        )
        if not (device_backed or removable):
            continue
        observations.append(
            Observation(
                kind=KIND_MOUNT,
                identity=f"mount:{target}",
                label=f"mount {source} -> {target} ({fstype})",
                attributes={
                    "source": source,
                    "target": target,
                    "fstype": fstype,
                    "options": options,
                    "read_only": options.split(",")[0] == "ro",
                    "device_backed": device_backed,
                    "removable_path": removable,
                },
            )
        )
    return observations


class MountProbe(Probe):
    name = "mounts"
    description = "Filesystem mounts backed by a device or under removable-media paths"

    def availability(self) -> ProbeAvailability:
        if Path(PROC_MOUNTS).exists():
            return ProbeAvailability(ok=True)
        return ProbeAvailability(ok=False, detail=f"{PROC_MOUNTS} not present")

    def snapshot(self) -> list[Observation]:
        path = Path(PROC_MOUNTS)
        if not path.exists():
            raise RuntimeError(f"{PROC_MOUNTS} not present")
        return parse_proc_mounts(path.read_text(encoding="utf-8", errors="ignore"))


# --------------------------------------------------------------------------
# pci / thunderbolt
# --------------------------------------------------------------------------

_PCI_CLASS_NAMES = {
    "0c03": "usb-controller",
    "0200": "ethernet",
    "0280": "network",
    "0300": "display",
    "0108": "nvme",
    "0106": "sata",
}


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None


def scan_pci_sysfs(
    pci_root: str = SYS_BUS_PCI, tb_root: str = SYS_BUS_THUNDERBOLT
) -> list[Observation]:
    observations: list[Observation] = []

    base = Path(pci_root)
    if base.is_dir():
        for entry in sorted(base.iterdir()):
            vendor = (_read(entry / "vendor") or "").replace("0x", "")
            device = (_read(entry / "device") or "").replace("0x", "")
            pci_class = (_read(entry / "class") or "").replace("0x", "")
            driver = None
            drv = entry / "driver"
            if drv.is_symlink() or drv.exists():
                try:
                    driver = drv.resolve().name
                except OSError:
                    driver = None
            observations.append(
                Observation(
                    kind=KIND_PCI_DEVICE,
                    identity=f"pci:{entry.name}",
                    label=f"PCI device {entry.name} [{vendor}:{device}]"
                    + (f" ({driver})" if driver else ""),
                    attributes={
                        "slot": entry.name,
                        "vendor_id": vendor,
                        "device_id": device,
                        "class": pci_class,
                        "class_name": _PCI_CLASS_NAMES.get(pci_class[:4], None),
                        "driver": driver,
                        "bus": "pci",
                    },
                )
            )

    tb_base = Path(tb_root)
    if tb_base.is_dir():
        for entry in sorted(tb_base.iterdir()):
            if not (entry / "device_name").exists() and not (entry / "vendor_name").exists():
                continue
            observations.append(
                Observation(
                    kind=KIND_PCI_DEVICE,
                    identity=f"thunderbolt:{entry.name}",
                    label=(
                        f"Thunderbolt device {entry.name}: "
                        f"{_read(entry / 'device_name') or '?'}"
                    ),
                    attributes={
                        "name": entry.name,
                        "device_name": _read(entry / "device_name"),
                        "vendor_name": _read(entry / "vendor_name"),
                        "authorized": _read(entry / "authorized"),
                        "bus": "thunderbolt",
                    },
                )
            )
    return observations


class PciDeviceProbe(Probe):
    name = "pci"
    description = "PCI and Thunderbolt device inventory (USB4/TBT PCIe-tunnel surface)"
    # PCI enumeration is stable within a phase; boundary snapshots are enough.
    samples_periodically = False

    def availability(self) -> ProbeAvailability:
        if Path(SYS_BUS_PCI).is_dir() or Path(SYS_BUS_THUNDERBOLT).is_dir():
            return ProbeAvailability(ok=True)
        return ProbeAvailability(
            ok=False, detail="neither /sys/bus/pci nor /sys/bus/thunderbolt present"
        )

    def snapshot(self) -> list[Observation]:
        return scan_pci_sysfs(SYS_BUS_PCI, SYS_BUS_THUNDERBOLT)
