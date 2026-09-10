# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Network interface inventory via psutil + sysfs.

A new network interface appearing when the cable is connected (USB CDC/RNDIS/NCM
gadget) is a high-value signal: it can be used to route or intercept traffic.
"""

from __future__ import annotations

import socket
from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_NETWORK_INTERFACE, Observation

try:
    import psutil
except Exception:  # pragma: no cover - defensive
    psutil = None  # type: ignore[assignment]

from cableprobe.probes.base import Probe, ProbeAvailability

log = get_logger("probe.network")

_LOOPBACKISH = ("lo",)


def _sysfs_driver(iface: str) -> str | None:
    link = Path(f"/sys/class/net/{iface}/device/driver")
    try:
        return link.resolve().name
    except OSError:
        return None


def _is_usb(iface: str) -> bool:
    link = Path(f"/sys/class/net/{iface}/device")
    try:
        return "usb" in str(link.resolve()).lower()
    except OSError:
        return False


def build_interface_observations(
    if_addrs: dict, if_stats: dict
) -> list[Observation]:
    observations: list[Observation] = []
    for iface, addrs in if_addrs.items():
        if iface in _LOOPBACKISH:
            continue
        mac = None
        ip_addresses: list[str] = []
        for addr in addrs:
            family = getattr(addr, "family", None)
            if family == getattr(psutil, "AF_LINK", None) or family == getattr(
                socket, "AF_PACKET", None
            ):
                mac = addr.address
            elif family in (socket.AF_INET, socket.AF_INET6):
                ip_addresses.append(addr.address)
        stats = if_stats.get(iface)
        observations.append(
            Observation(
                kind=KIND_NETWORK_INTERFACE,
                identity=f"net:{iface}",
                label=f"network interface {iface}"
                + (f" ({mac})" if mac else ""),
                attributes={
                    "interface": iface,
                    "mac": mac,
                    "is_up": bool(getattr(stats, "isup", False)) if stats else None,
                    "speed_mbps": getattr(stats, "speed", None) if stats else None,
                    "mtu": getattr(stats, "mtu", None) if stats else None,
                    "driver": _sysfs_driver(iface),
                    "is_usb": _is_usb(iface),
                    "ip_addresses": sorted(ip_addresses),
                },
            )
        )
    return observations


class NetworkInterfaceProbe(Probe):
    name = "network"
    description = "Inventory of network interfaces (driver, transport, addresses)"

    def availability(self) -> ProbeAvailability:
        if psutil is None:
            return ProbeAvailability(ok=False, detail="psutil not available")
        return ProbeAvailability(ok=True)

    def snapshot(self) -> list[Observation]:
        if psutil is None:
            raise RuntimeError("psutil not available")
        return build_interface_observations(
            psutil.net_if_addrs(), psutil.net_if_stats()
        )
