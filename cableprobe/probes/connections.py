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

Between the phase-boundary snapshots the probe also samples the active
connections in the background (``connections_sample_interval_seconds``) and
emits a compact per-remote ``connection_frequency`` observation - "seen in N of
M samples" - at each boundary. A single glimpse of a connection caught by the
point-in-time snapshot can be a timing coincidence with a legitimate background
process; the same remote showing up across most of the phase's samples is a
beaconing pattern, not a one-off.
"""

from __future__ import annotations

import ipaddress
import threading
from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import (
    KIND_CONNECTION_FREQUENCY,
    KIND_OUTBOUND_CONNECTION,
    Observation,
)
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


def active_remotes(text: str, *, ipv6: bool = False) -> set[tuple[str, str]]:
    """``{(proto, remote_ep), ...}`` of routable remotes with an active
    connection - the lightweight read used for frequency sampling, without
    building a full :class:`Observation` per row."""

    proto = "tcp6" if ipv6 else "tcp"
    out: set[tuple[str, str]] = set()
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] not in _ACTIVE_STATES:
            continue
        remote_ep, _ = _decode_proc_net_address(fields[2], ipv6=ipv6)
        if _is_routable_remote(remote_ep):
            out.add((proto, remote_ep))
    return out


class ConnectionProbe(Probe):
    name = "connections"
    description = "Outbound TCP connections to routable hosts (isolated test host only)"

    def __init__(self, config, session_start: float) -> None:
        super().__init__(config, session_start)
        self._sample_interval = max(
            0.1, float(config.probes.connections_sample_interval_seconds)
        )
        self._repeat_threshold = max(1, int(config.probes.connections_repeat_threshold))

        self._lock = threading.Lock()
        self._counts: dict[tuple[str, str], int] = {}
        self._sample_count = 0
        self._sampler_stop = threading.Event()
        self._sampler: threading.Thread | None = None

    def availability(self) -> ProbeAvailability:
        if Path(PROC_NET_TCP).exists():
            return ProbeAvailability(ok=True)
        return ProbeAvailability(ok=False, detail=f"{PROC_NET_TCP} not present")

    # -- frequency sampling ------------------------------------------------

    def _sample_once(self) -> None:
        seen: set[tuple[str, str]] = set()
        for path, ipv6 in ((PROC_NET_TCP, False), (PROC_NET_TCP6, True)):
            p = Path(path)
            if not p.exists():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            seen |= active_remotes(text, ipv6=ipv6)
        with self._lock:
            self._sample_count += 1
            for key in seen:
                self._counts[key] = self._counts.get(key, 0) + 1

    def _drain_window(self) -> tuple[dict[tuple[str, str], int], int]:
        with self._lock:
            counts, total = dict(self._counts), self._sample_count
            self._counts.clear()
            self._sample_count = 0
        return counts, total

    def _run_sampler(self) -> None:
        while not self._sampler_stop.wait(self._sample_interval):
            self._sample_once()

    def _frequency_observations(self) -> list[Observation]:
        counts, total = self._drain_window()
        if not total:
            return []
        observations = []
        for (proto, remote), seen_count in sorted(counts.items()):
            repeated = seen_count >= self._repeat_threshold
            observations.append(
                Observation(
                    kind=KIND_CONNECTION_FREQUENCY,
                    identity=f"conn:freq:{proto}:{remote}",
                    label=(
                        f"{proto} to {remote}: seen in {seen_count}/{total} samples"
                    ),
                    attributes={
                        "protocol": proto,
                        "remote": remote,
                        "seen_count": seen_count,
                        "sample_count": total,
                        "frequency": round(seen_count / total, 2),
                        "repeat_threshold": self._repeat_threshold,
                        "repeated": repeated,
                    },
                )
            )
        return observations

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        self._sampler_stop.clear()
        self._sampler = threading.Thread(
            target=self._run_sampler, name="cableprobe-connections-sampler", daemon=True
        )
        self._sampler.start()

    async def stop(self) -> None:
        self._sampler_stop.set()
        if self._sampler is not None:
            self._sampler.join(timeout=2.0)
            self._sampler = None

    def snapshot(self) -> list[Observation]:
        out: list[Observation] = []
        for path, ipv6 in ((PROC_NET_TCP, False), (PROC_NET_TCP6, True)):
            p = Path(path)
            if p.exists():
                out += parse_outbound(
                    p.read_text(encoding="utf-8", errors="ignore"), ipv6=ipv6
                )
        out += self._frequency_observations()
        return out
