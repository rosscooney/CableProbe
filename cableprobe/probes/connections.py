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
from cableprobe.probes.base import BackgroundSampler, Probe, ProbeAvailability
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


def _outbound_row(
    fields: list[str], *, ipv6: bool
) -> tuple[str, str, str, str, str] | None:
    """``(proto, remote_ep, local_ep, label_state, uid)`` for one
    ``/proc/net/tcp{,6}`` row, or ``None`` if it is not a routable,
    active-state connection. Shared by :func:`parse_outbound` (whole-text,
    for small/test input) and the streaming path (large real reads)."""

    if len(fields) < 10:
        return None
    local, remote, state, uid = fields[1], fields[2], fields[3], fields[7]
    label_state = _ACTIVE_STATES.get(state)
    if label_state is None:
        return None
    remote_ep, _ = _decode_proc_net_address(remote, ipv6=ipv6)
    if not _is_routable_remote(remote_ep):
        return None
    local_ep, _ = _decode_proc_net_address(local, ipv6=ipv6)
    return ("tcp6" if ipv6 else "tcp"), remote_ep, local_ep, label_state, uid


def _observation_from_row(row: tuple[str, str, str, str, str]) -> Observation:
    proto, remote_ep, local_ep, label_state, uid = row
    return Observation(
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


def parse_outbound(text: str, *, ipv6: bool = False) -> list[Observation]:
    observations: list[Observation] = []
    for line in text.splitlines()[1:]:
        row = _outbound_row(line.split(), ipv6=ipv6)
        if row is not None:
            observations.append(_observation_from_row(row))
    return observations


def _stream_outbound_observations(
    path: Path, *, ipv6: bool, cap: int
) -> tuple[list[Observation], bool]:
    """Like :func:`parse_outbound`, but reads ``path`` line by line - never
    holding the whole table in memory at once - and stops as soon as ``cap``
    observations have been built, regardless of how many rows remain.
    Returns ``(observations, truncated)``."""

    observations: list[Observation] = []
    truncated = False
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        next(fh, None)  # header row
        for line in fh:
            row = _outbound_row(line.split(), ipv6=ipv6)
            if row is None:
                continue
            if len(observations) >= cap:
                truncated = True
                break
            observations.append(_observation_from_row(row))
    return observations, truncated


#: Cap on distinct (proto, remote) keys tracked in one drain window. Every
#: other buffer in this codebase is bounded (the power probe's ring, the
#: command-output cap, the per-phase event budget); this dict was the
#: exception - a host with real traffic (against the probe's own
#: isolated-host caveat), or a device that behaves like a scanner/flooder,
#: could otherwise grow it without limit for the length of a whole phase.
#: Once the cap is hit, a remote already being tracked keeps accumulating -
#: only brand-new remotes stop being added - so an actual beaconing pattern is
#: never the one thing that gets dropped.
_MAX_TRACKED_REMOTES = 2000

#: Cap on distinct entries collected from ONE proc-net-tcp read, independent
#: of _MAX_TRACKED_REMOTES (which caps what survives *across* a whole phase).
#: Without this, a single read built the full set of every distinct remote in
#: the table before the cross-window cap ever got a chance to look at it - a
#: host with a very large connection table (or a device behaving like a
#: scanner/flooder) could balloon memory on one sampling tick even though the
#: tracked-remote cap looked bounded. Streaming + this cap bounds the
#: intermediate collection itself, not just what is kept afterwards.
_MAX_REMOTES_PER_READ = 4000

#: Same idea for the point-in-time snapshot observations - one Observation per
#: distinct connection, previously uncapped unlike every other bounded
#: structure in this codebase.
_MAX_SNAPSHOT_OBSERVATIONS = 2000


def _accumulate(
    counts: dict[tuple[str, str], int], seen: set[tuple[str, str]], *, cap: int
) -> bool:
    """Bump ``counts[key]`` for each ``key`` in ``seen``, refusing to grow past
    ``cap`` distinct keys. Returns True if any new key was refused."""

    capped = False
    for key in seen:
        if key not in counts and len(counts) >= cap:
            capped = True
            continue
        counts[key] = counts.get(key, 0) + 1
    return capped


def active_remotes(text: str, *, ipv6: bool = False) -> set[tuple[str, str]]:
    """``{(proto, remote_ep), ...}`` of routable remotes with an active
    connection - the lightweight read used for frequency sampling, without
    building a full :class:`Observation` per row."""

    out: set[tuple[str, str]] = set()
    for line in text.splitlines()[1:]:
        row = _outbound_row(line.split(), ipv6=ipv6)
        if row is not None:
            out.add((row[0], row[1]))
    return out


def _stream_active_remotes(
    path: Path, *, ipv6: bool, cap: int
) -> tuple[set[tuple[str, str]], bool]:
    """Like :func:`active_remotes`, but reads ``path`` line by line and stops
    collecting once ``cap`` distinct entries have been found - the
    intermediate set itself never grows past that, regardless of how many
    rows the table actually has. Returns ``(remotes, truncated)``."""

    seen: set[tuple[str, str]] = set()
    truncated = False
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        next(fh, None)  # header row
        for line in fh:
            row = _outbound_row(line.split(), ipv6=ipv6)
            if row is None:
                continue
            entry = (row[0], row[1])
            if entry in seen:
                continue
            if len(seen) >= cap:
                truncated = True
                break
            seen.add(entry)
    return seen, truncated


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
        self._remotes_capped = False
        self._read_failures = 0
        self._reads_truncated = 0
        self._sampler: BackgroundSampler | None = None

    def availability(self) -> ProbeAvailability:
        if Path(PROC_NET_TCP).exists():
            return ProbeAvailability(ok=True)
        return ProbeAvailability(ok=False, detail=f"{PROC_NET_TCP} not present")

    # -- frequency sampling ------------------------------------------------

    def _sample_once(self) -> None:
        seen: set[tuple[str, str]] = set()
        attempted = 0
        read_failed = 0
        read_truncated = False
        for path, ipv6 in ((PROC_NET_TCP, False), (PROC_NET_TCP6, True)):
            p = Path(path)
            if not p.exists():
                continue  # not present on this host (e.g. IPv6 disabled) - expected
            attempted += 1
            try:
                # streamed line-by-line and capped at _MAX_REMOTES_PER_READ -
                # the intermediate set from ONE read never grows past that,
                # regardless of how large the actual table is
                entries, this_truncated = _stream_active_remotes(
                    p, ipv6=ipv6, cap=_MAX_REMOTES_PER_READ
                )
            except OSError:
                read_failed += 1
                continue
            seen |= entries
            read_truncated = read_truncated or this_truncated

        warn = False
        with self._lock:
            if read_failed:
                self._read_failures += 1
            if read_truncated:
                self._reads_truncated += 1
            if attempted and read_failed == attempted:
                # every read this tick failed - nothing was actually observed.
                # Do not bump sample_count or merge the (empty) `seen`: that
                # would make a failed sample look identical to "sampled, found
                # nothing", silently understating how often a remote was
                # really there.
                return
            self._sample_count += 1
            hit_cap = _accumulate(self._counts, seen, cap=_MAX_TRACKED_REMOTES)
            warn = hit_cap and not self._remotes_capped
            if warn:
                self._remotes_capped = True
        if warn:
            log.warning(
                "connections probe: more than %d distinct remotes seen in one "
                "window - frequency counts for further new ones are not tracked "
                "until the next phase boundary",
                _MAX_TRACKED_REMOTES,
            )

    def _drain_window(self) -> tuple[dict[tuple[str, str], int], int, bool, int, int]:
        """Returns ``(counts, sample_count, was_capped, read_failures,
        reads_truncated)`` for the window and resets all five for the next
        one.

        The capped / failure / truncation state is read out *before* being
        reset, so anything that went wrong during this window is handed to
        the caller (which folds it into a ``monitoring_incomplete``
        observation) rather than being silently discarded by the reset that
        immediately follows.
        """

        with self._lock:
            counts, total = dict(self._counts), self._sample_count
            capped = self._remotes_capped
            read_failures, reads_truncated = self._read_failures, self._reads_truncated
            self._counts.clear()
            self._sample_count = 0
            self._remotes_capped = False
            self._read_failures = 0
            self._reads_truncated = 0
        return counts, total, capped, read_failures, reads_truncated

    def _frequency_observations(self) -> list[Observation]:
        counts, total, capped, read_failures, reads_truncated = self._drain_window()
        observations: list[Observation] = []

        if capped or read_failures or reads_truncated:
            reasons = []
            if capped:
                reasons.append(
                    f"more than {_MAX_TRACKED_REMOTES} distinct remotes seen in one window"
                )
            if reads_truncated:
                reasons.append(
                    f"{reads_truncated} read(s) hit the per-read cap of "
                    f"{_MAX_REMOTES_PER_READ} entries"
                )
            if read_failures:
                reasons.append(
                    f"{read_failures} sample(s) could not read /proc/net/tcp{{,6}}"
                )
            reason = "; ".join(reasons)
            observations.append(
                Observation(
                    kind=KIND_CONNECTION_FREQUENCY,
                    identity="conn:freq:incomplete",
                    label=f"connection frequency sampling was incomplete ({reason})",
                    attributes={"monitoring_incomplete": True, "reason": reason},
                )
            )

        if not total:
            return observations
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
        self._sampler = BackgroundSampler(
            self._sample_once, self._sample_interval, name="cableprobe-connections-sampler"
        )
        self._sampler.start()

    async def stop(self) -> None:
        if self._sampler is not None:
            self._sampler.stop()
            self._sampler = None

    def snapshot(self) -> list[Observation]:
        out: list[Observation] = []
        truncated = False
        for path, ipv6 in ((PROC_NET_TCP, False), (PROC_NET_TCP6, True)):
            p = Path(path)
            if not p.exists():
                continue
            # streamed line-by-line and capped at _MAX_SNAPSHOT_OBSERVATIONS,
            # unlike a plain parse_outbound(p.read_text(...)) which would
            # build one Observation per row for however large the table is
            obs, this_truncated = _stream_outbound_observations(
                p, ipv6=ipv6, cap=_MAX_SNAPSHOT_OBSERVATIONS
            )
            out += obs
            truncated = truncated or this_truncated
        if truncated:
            out.append(
                Observation(
                    kind=KIND_CONNECTION_FREQUENCY,
                    identity="conn:snapshot:incomplete",
                    label=(
                        "the outbound-connection snapshot was truncated at "
                        f"{_MAX_SNAPSHOT_OBSERVATIONS} entries"
                    ),
                    attributes={
                        "monitoring_incomplete": True,
                        "reason": (
                            f"snapshot observation cap ({_MAX_SNAPSHOT_OBSERVATIONS}) hit"
                        ),
                    },
                )
            )
        out += self._frequency_observations()
        return out
