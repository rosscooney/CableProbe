# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Outbound TCP connections to non-loopback hosts.

On a properly isolated test host there should be *no* outbound network activity.
A connection that appears in correlation with the cable - especially to a host
on a network the cable itself created - is the cable's payload or gadget
phoning home.

Off by default: on a host with normal internet access this fires on every
package update, NTP sync and telemetry ping. Enable it in ``probes.enabled``
when the test host really is isolated.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_OUTBOUND_CONNECTION, Observation
from cableprobe.probes.base import Probe, ProbeAvailability
from cableprobe.probes.network_state import (
    PROC_NET_TCP,
    PROC_NET_TCP6,
    _decode_proc_net_address,
    _int,
)

log = get_logger("probe.connections")

# TCP states from include/net/tcp_states.h
_ACTIVE_STATES = {"01": "established", "02": "syn_sent", "03": "syn_recv"}


def _is_routable_remote(endpoint: str) -> bool:
    host = endpoint.rsplit(":", 1)[0].strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast)


def parse_outbound(text: str, *, ipv6: bool = False) -> list[Observation]:
    proto = "tcp6" if ipv6 else "tcp"
    observations: list[Observation] = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        local, remote, state, uid = fields[1], fields[2], fields[3], fields[7]
        label_state = _ACTIVE_STATES.get(state)
        if label_state is None:
            continue
        remote_ep, _ = _decode_proc_net_address(remote, ipv6=ipv6)
        if not _is_routable_remote(remote_ep):
            continue
        local_ep, _ = _decode_proc_net_address(local, ipv6=ipv6)
        observations.append(
            Observation(
                kind=KIND_OUTBOUND_CONNECTION,
                identity=f"conn:{proto}:{remote_ep}",
                label=f"{proto} {local_ep} -> {remote_ep} ({label_state})",
                attributes={
                    "protocol": proto,
                    "remote": remote_ep,
                    "local": local_ep,
                    "state": label_state,
                    "uid": _int(uid),
                },
            )
        )
    return observations


class ConnectionProbe(Probe):
    name = "connections"
    description = "Outbound TCP connections to routable hosts (isolated test host only)"

    def availability(self) -> ProbeAvailability:
        if Path(PROC_NET_TCP).exists():
            return ProbeAvailability(ok=True)
        return ProbeAvailability(ok=False, detail=f"{PROC_NET_TCP} not present")

    def snapshot(self) -> list[Observation]:
        out: list[Observation] = []
        for path, ipv6 in ((PROC_NET_TCP, False), (PROC_NET_TCP6, True)):
            p = Path(path)
            if p.exists():
                out += parse_outbound(
                    p.read_text(encoding="utf-8", errors="ignore"), ipv6=ipv6
                )
        return out
