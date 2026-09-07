# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Network *behaviour* probes.

A USB ethernet gadget appearing (covered by the ``network`` probe) is not the
attack -- the attack is what it then does to routing and name resolution:

* ``routing`` -- the default route and the configured DNS resolvers. A cable
  gadget that becomes the default route, or that moves ``/etc/resolv.conf``,
  shows up here as a *modified* ``network_config`` delta.
* ``listeners`` -- TCP sockets in LISTEN state. A process that starts listening
  in correlation with the cable connection is worth surfacing.

Both parse ``/proc/net`` directly so they need no external tools and are unit
testable; ``listeners`` additionally uses ``ss`` when present to attribute the
owning process.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_LISTENING_SOCKET, KIND_NETWORK_CONFIG, Observation
from cableprobe.probes.base import Probe, ProbeAvailability, have_tool, run_command

log = get_logger("probe.network_state")

PROC_NET_ROUTE = "/proc/net/route"
PROC_NET_TCP = "/proc/net/tcp"
PROC_NET_TCP6 = "/proc/net/tcp6"
PROC_IP_LOCAL_PORT_RANGE = "/proc/sys/net/ipv4/ip_local_port_range"
ETC_RESOLV_CONF = "/etc/resolv.conf"

_TCP_LISTEN = "0A"  # state code for LISTEN in /proc/net/tcp{,6}

#: Fallback lower bound of the ephemeral port range (Linux default). Sockets
#: that LISTEN on a port at or above this are almost always short-lived
#: framework noise (RPC, peer discovery, IDE remote helpers, ...) rather than a
#: service -- and no implant would bind a backdoor to a port that changes on
#: every restart -- so they are dropped to keep the report signal-dense.
DEFAULT_EPHEMERAL_MIN = 32768


# --------------------------------------------------------------------------
# routing / DNS
# --------------------------------------------------------------------------


def _decode_le_ipv4(hex_addr: str) -> str:
    """``0100A8C0`` (little-endian, as in /proc/net/route) -> ``192.168.0.1``."""

    try:
        return socket.inet_ntoa(struct.pack("<L", int(hex_addr, 16)))
    except (ValueError, OSError):
        return hex_addr


def parse_proc_net_route(text: str) -> list[dict]:
    """Return the default-route rows from ``/proc/net/route``."""

    rows: list[dict] = []
    lines = text.splitlines()
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 11:
            continue
        iface, destination, gateway = fields[0], fields[1], fields[2]
        if destination != "00000000":
            continue
        rows.append(
            {
                "interface": iface,
                "gateway": _decode_le_ipv4(gateway),
                "metric": _int(fields[6]),
                "flags": fields[3],
            }
        )
    return rows


def parse_resolv_conf(text: str) -> list[str]:
    servers: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                servers.append(parts[1])
    return servers


def _int(value: str) -> int | str:
    try:
        return int(value)
    except ValueError:
        return value


def build_network_config_observations(
    route_rows: list[dict], dns_servers: list[str]
) -> list[Observation]:
    observations: list[Observation] = []

    if route_rows:
        # Lowest metric wins as the effective default route.
        best = sorted(
            route_rows, key=lambda r: r["metric"] if isinstance(r["metric"], int) else 0
        )[0]
        observations.append(
            Observation(
                kind=KIND_NETWORK_CONFIG,
                identity="route:default",
                label=f"default route via {best['gateway']} dev {best['interface']}",
                attributes={
                    "interface": best["interface"],
                    "gateway": best["gateway"],
                    "metric": best["metric"],
                    "all_default_routes": sorted(
                        f"{r['interface']}:{r['gateway']}" for r in route_rows
                    ),
                },
            )
        )

    if dns_servers:
        observations.append(
            Observation(
                kind=KIND_NETWORK_CONFIG,
                identity="dns:resolvers",
                label=f"DNS resolvers: {', '.join(dns_servers)}",
                attributes={
                    "nameservers": list(dns_servers),
                    "count": len(dns_servers),
                    "primary": dns_servers[0],
                },
            )
        )
    return observations


class RoutingProbe(Probe):
    name = "routing"
    description = "Default route and DNS resolvers (catches gateway / resolver hijack)"

    def availability(self) -> ProbeAvailability:
        if Path(PROC_NET_ROUTE).exists():
            return ProbeAvailability(ok=True)
        return ProbeAvailability(ok=False, detail=f"{PROC_NET_ROUTE} not present")

    def snapshot(self) -> list[Observation]:
        route_rows: list[dict] = []
        route_path = Path(PROC_NET_ROUTE)
        if route_path.exists():
            route_rows = parse_proc_net_route(
                route_path.read_text(encoding="utf-8", errors="ignore")
            )
        dns_servers: list[str] = []
        resolv = Path(ETC_RESOLV_CONF)
        if resolv.exists():
            dns_servers = parse_resolv_conf(
                resolv.read_text(encoding="utf-8", errors="ignore")
            )
        return build_network_config_observations(route_rows, dns_servers)


# --------------------------------------------------------------------------
# listening sockets
# --------------------------------------------------------------------------


def _decode_proc_net_address(hex_addr: str, *, ipv6: bool) -> tuple[str, int | None]:
    """``<hex ip>:<hex port>`` -> (``ip:port`` string, port number)."""

    addr, _, port = hex_addr.partition(":")
    try:
        port_num = int(port, 16)
    except ValueError:
        return hex_addr, None
    try:
        if ipv6:
            packed = bytes.fromhex(addr)
            # /proc stores each 32-bit word little-endian.
            packed = b"".join(
                packed[i : i + 4][::-1] for i in range(0, len(packed), 4)
            )
            ip = socket.inet_ntop(socket.AF_INET6, packed)
            return f"[{ip}]:{port_num}", port_num
        ip = socket.inet_ntoa(struct.pack("<L", int(addr, 16)))
    except (ValueError, OSError):
        return hex_addr, port_num
    return f"{ip}:{port_num}", port_num


def parse_proc_net_tcp(
    text: str, *, ipv6: bool = False, ephemeral_min: int = DEFAULT_EPHEMERAL_MIN
) -> list[Observation]:
    """Parse ``/proc/net/tcp`` or ``/proc/net/tcp6`` -> LISTEN socket observations.

    Sockets listening on an ephemeral-range port (>= ``ephemeral_min``) are
    skipped -- they churn on their own and never carry a backdoor signal.
    """

    observations: list[Observation] = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        local, state, uid, inode = fields[1], fields[3], fields[7], fields[9]
        if state != _TCP_LISTEN:
            continue
        endpoint, port = _decode_proc_net_address(local, ipv6=ipv6)
        if port is not None and port >= ephemeral_min:
            continue
        proto = "tcp6" if ipv6 else "tcp"
        observations.append(
            Observation(
                kind=KIND_LISTENING_SOCKET,
                identity=f"listen:{proto}:{endpoint}",
                label=f"{proto} listening on {endpoint}",
                attributes={
                    "protocol": proto,
                    "endpoint": endpoint,
                    "port": port,
                    "uid": _int(uid),
                    "inode": inode,
                },
            )
        )
    return observations


def ephemeral_port_min(path: str = PROC_IP_LOCAL_PORT_RANGE) -> int:
    """Lower bound of the kernel's ephemeral port range, or the default."""

    try:
        lo = Path(path).read_text(encoding="utf-8").split()[0]
        return int(lo)
    except (OSError, ValueError, IndexError):
        return DEFAULT_EPHEMERAL_MIN


def annotate_with_ss(observations: list[Observation], ss_output: str) -> None:
    """Best-effort: fill ``process`` from ``ss -tlnpH`` output, matched on endpoint."""

    by_endpoint: dict[str, str] = {}
    for line in ss_output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        process = ""
        if "users:((" in line:
            process = line.split("users:((", 1)[1].rstrip(")")
        by_endpoint[local] = process
    for obs in observations:
        endpoint = obs.attributes.get("endpoint", "")
        # ss prints ``*`` / ``0.0.0.0`` / ``[::]`` for the wildcard; match on port.
        port = endpoint.rsplit(":", 1)[-1]
        for key, proc in by_endpoint.items():
            if key.rsplit(":", 1)[-1] == port and proc:
                obs.attributes["process"] = proc
                break


class ListenerProbe(Probe):
    name = "listeners"
    description = "TCP sockets in LISTEN state (new listeners correlated with connect)"

    def availability(self) -> ProbeAvailability:
        if Path(PROC_NET_TCP).exists():
            return ProbeAvailability(ok=True)
        return ProbeAvailability(ok=False, detail=f"{PROC_NET_TCP} not present")

    def snapshot(self) -> list[Observation]:
        observations: list[Observation] = []
        ephemeral_min = ephemeral_port_min()
        tcp = Path(PROC_NET_TCP)
        if tcp.exists():
            observations += parse_proc_net_tcp(
                tcp.read_text(encoding="utf-8", errors="ignore"),
                ephemeral_min=ephemeral_min,
            )
        tcp6 = Path(PROC_NET_TCP6)
        if tcp6.exists():
            observations += parse_proc_net_tcp(
                tcp6.read_text(encoding="utf-8", errors="ignore"),
                ipv6=True,
                ephemeral_min=ephemeral_min,
            )
        if observations and have_tool("ss"):
            code, out, _ = run_command(["ss", "-tlnpH"], timeout=5.0)
            if code == 0:
                annotate_with_ss(observations, out)
        return observations
