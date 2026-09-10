# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Phase comparison: turn three PhaseObservations into a list of Deltas."""

from __future__ import annotations

from cableprobe.logging_config import get_logger
from cableprobe.models import (
    KIND_LISTENING_SOCKET,
    PHASE_BASELINE,
    PHASE_POST_TEST,
    PHASE_TEST,
    AttributeChange,
    Delta,
    Observation,
    PhaseObservation,
    ProbeEvent,
)

log = get_logger("analysis")

#: Attribute keys that change on their own and must not trigger "modified".
VOLATILE_KEYS = {
    "device",
    "devnum",
    "busnum",
    "minor",
    "major",
    "devpath",
    "DEVPATH",
    "create_time",
    "pid",
    "ppid",
    "source",
    "bus",
    "raw",
    "ip_addresses",
    "refcount",
    "inode",
    "vconn_source",
    "signal_dbm",
    "strong_signal",
    "channel",
    "freq",
    "current_ma",
    "delta_ma",
    "bus_voltage_v",
    "baseline_ma",
    "local",
    "state",
}

_ADD_ACTIONS = {"add", "bind", "online"}
_REMOVE_ACTIONS = {"remove", "unbind", "offline"}

#: Kinds where "appeared during test, still present after disconnect" is a
#: genuine "something was left on the host" red flag. Kernel log lines (which
#: only ever accumulate), processes, the topology summary and config-style
#: observations are deliberately excluded - counting them makes a routine
#: session look alarming.
PERSISTENCE_KINDS = {
    "usb_device",
    "usb_interface",
    "input_device",
    "hid_device",
    "network_interface",
    "block_device",
    "serial_device",
    "audio_device",
    "video_device",
    "pci_device",
    "mount",
}


def _diff_attributes(before: dict, after: dict) -> list[AttributeChange]:
    changes: list[AttributeChange] = []
    keys = (set(before) | set(after)) - VOLATILE_KEYS
    for key in sorted(keys):
        b = before.get(key)
        a = after.get(key)
        if b != a:
            changes.append(AttributeChange(key=key, before=b, after=a))
    return changes


def _index_events(
    events: list[ProbeEvent],
) -> dict[tuple[str, str], list[ProbeEvent]]:
    """``(kind, identity) -> events``, built once instead of rescanning the
    whole list for every delta."""

    index: dict[tuple[str, str], list[ProbeEvent]] = {}
    for event in events:
        index.setdefault((event.kind, event.identity), []).append(event)
    return index


def analyse(phases: dict[str, PhaseObservation]) -> list[Delta]:
    """Compare baseline / test / post-test end snapshots and phase events."""

    baseline = phases[PHASE_BASELINE].end_snapshot.index()
    test = phases[PHASE_TEST].end_snapshot.index()
    post = phases[PHASE_POST_TEST].end_snapshot.index()

    test_by_key = _index_events(phases[PHASE_TEST].events)
    post_by_key = _index_events(phases[PHASE_POST_TEST].events)

    def test_events_for(kind: str, identity: str) -> list[ProbeEvent]:
        return test_by_key.get((kind, identity), [])

    def post_events_for(kind: str, identity: str) -> list[ProbeEvent]:
        return post_by_key.get((kind, identity), [])

    keys = set(baseline) | set(test) | set(post)
    deltas: list[Delta] = []

    for key in sorted(keys):
        kind, identity = key
        in_base = key in baseline
        in_test = key in test
        in_post = key in post
        present_in = {
            PHASE_BASELINE: in_base,
            PHASE_TEST: in_test,
            PHASE_POST_TEST: in_post,
        }
        current: Observation = test.get(key) or post.get(key) or baseline[key]

        if not in_base and in_test:
            deltas.append(
                Delta(
                    change="appeared",
                    kind=kind,
                    identity=identity,
                    label=current.label,
                    first_seen_phase=PHASE_TEST,
                    present_in=present_in,
                    reverted_after_disconnect=not in_post,
                    attributes=current.attributes,
                    related_events=test_events_for(kind, identity),
                )
            )
        elif not in_base and not in_test and in_post:
            deltas.append(
                Delta(
                    change="appeared",
                    kind=kind,
                    identity=identity,
                    label=current.label,
                    first_seen_phase=PHASE_POST_TEST,
                    present_in=present_in,
                    reverted_after_disconnect=False,
                    attributes=current.attributes,
                    related_events=post_events_for(kind, identity),
                )
            )
        elif in_base and not in_test:
            deltas.append(
                Delta(
                    change="disappeared",
                    kind=kind,
                    identity=identity,
                    label=baseline[key].label,
                    first_seen_phase=None,
                    present_in=present_in,
                    reverted_after_disconnect=in_post,
                    attributes=baseline[key].attributes,
                    related_events=test_events_for(kind, identity),
                )
            )
        elif in_base and in_test:
            changes = _diff_attributes(baseline[key].attributes, test[key].attributes)
            if changes:
                deltas.append(
                    Delta(
                        change="modified",
                        kind=kind,
                        identity=identity,
                        label=test[key].label,
                        first_seen_phase=PHASE_TEST,
                        present_in=present_in,
                        attributes=test[key].attributes,
                        attribute_changes=changes,
                        related_events=test_events_for(kind, identity),
                    )
                )

        # A modification that lands only in post-test (e.g. a persistence file
        # rewritten after the cable was pulled) - independent of the branches
        # above, which only compare baseline vs test.
        if in_test and in_post:
            post_changes = _diff_attributes(
                test[key].attributes, post[key].attributes
            )
            if post_changes:
                deltas.append(
                    Delta(
                        change="modified",
                        kind=kind,
                        identity=identity,
                        label=post[key].label,
                        first_seen_phase=PHASE_POST_TEST,
                        present_in=present_in,
                        attributes=post[key].attributes,
                        attribute_changes=post_changes,
                        related_events=post_events_for(kind, identity),
                    )
                )

        # An established item that survived the test but is gone after the cable
        # was unplugged - a deletion during post-test. The (in_base, not in_test)
        # branch above only catches deletion by test-end.
        if in_base and in_test and not in_post:
            src = test[key]
            deltas.append(
                Delta(
                    change="disappeared",
                    kind=kind,
                    identity=identity,
                    label=src.label,
                    first_seen_phase=PHASE_POST_TEST,
                    present_in=present_in,
                    reverted_after_disconnect=False,
                    attributes=src.attributes,
                    related_events=post_events_for(kind, identity),
                )
            )

    # The end-snapshot comparison above misses anything that changes *and
    # reverts* between two end snapshots. Also compare the phase start snapshots
    # so a route / persistence change made on connect (or on disconnect) and
    # undone before the phase ends is still recorded.
    present_in_for = {
        (kind, ident): {
            PHASE_BASELINE: (kind, ident) in baseline,
            PHASE_TEST: (kind, ident) in test,
            PHASE_POST_TEST: (kind, ident) in post,
        }
        for kind, ident in keys
    }
    test_start = phases[PHASE_TEST].start_snapshot.index()
    post_start = phases[PHASE_POST_TEST].start_snapshot.index()
    for before_idx, after_idx, phase, events_for in (
        (baseline, test_start, PHASE_TEST, test_events_for),
        (test_start, test, PHASE_TEST, test_events_for),
        (test, post_start, PHASE_POST_TEST, post_events_for),
        (post_start, post, PHASE_POST_TEST, post_events_for),
    ):
        _boundary_deltas(
            deltas, before_idx, after_idx, present_in_for, phase, events_for
        )

    deltas.extend(
        _transient_deltas(deltas, baseline, test_by_key, phase=PHASE_TEST)
    )
    deltas.extend(
        _transient_deltas(
            deltas, {**baseline, **test}, post_by_key, phase=PHASE_POST_TEST
        )
    )
    return [d for d in deltas if not _is_ephemeral_listener_churn(d)]


def _is_ephemeral_listener_churn(d: Delta) -> bool:
    """An ephemeral-range listening socket that only came and went.

    RPC, mDNS, peer-discovery and IDE-helper sockets bind a fresh high port on
    every restart and drop it again on their own. Because the identity is keyed
    on the port number, every poll sees a different set of them "appear" and
    "disappear" - which buried the report in rows and fired
    ``transient-device-during-test`` / ``new-ephemeral-listener-on-connect`` on
    a host with nothing plugged in.

    A socket that deliberately binds a fixed port in the ephemeral range (a
    callback backdoor) is present across *more than one* steady-state snapshot;
    a high port seen in exactly one snapshot is the kernel handing a throwaway
    number to a short-lived socket. So: drop an ephemeral-listener delta unless
    the socket was seen in at least two phase snapshots.
    """

    if d.kind != KIND_LISTENING_SOCKET or not d.attributes.get("ephemeral_port"):
        return False
    return sum(1 for present in d.present_in.values() if present) < 2


def _change_signature(change: str, attribute_changes: list[AttributeChange]) -> tuple:
    """Identify a *transition* - so a boundary comparison is only skipped when
    an exactly-equal change is already recorded, not merely another change for
    the same device."""

    return (
        change,
        tuple(sorted((c.key, repr(c.before), repr(c.after)) for c in attribute_changes)),
    )


def _boundary_deltas(
    deltas: list[Delta],
    before_idx: dict[tuple[str, str], Observation],
    after_idx: dict[tuple[str, str], Observation],
    present_in_for: dict[tuple[str, str], dict[str, bool]],
    phase: str,
    events_for,
) -> None:
    """Compare two adjacent snapshots and record changes the end-snapshot pass
    could not see (a change made and undone within the phase).

    De-duplication is per *transition*: an identical change already recorded for
    this device+phase is skipped, but a different one - e.g. a blatant tamper at
    test-start that was partly walked back by test-end - is still recorded.
    """

    seen: dict[tuple[str, str], set[tuple]] = {}
    #: keys whose appear/disappear lifecycle the main comparison already
    #: described (in any phase) - a boundary presence flip adds nothing unless
    #: the item never settled into an end snapshot.
    main_presence_changes = {
        (d.kind, d.identity) for d in deltas if d.change in ("appeared", "disappeared")
    }
    for d in deltas:
        if d.first_seen_phase == phase:
            seen.setdefault((d.kind, d.identity), set()).add(
                _change_signature(d.change, d.attribute_changes)
            )

    absent = {PHASE_BASELINE: False, PHASE_TEST: False, PHASE_POST_TEST: False}

    def _record(delta: Delta) -> None:
        sig = _change_signature(delta.change, delta.attribute_changes)
        bucket = seen.setdefault((delta.kind, delta.identity), set())
        if sig in bucket:
            return
        bucket.add(sig)
        deltas.append(delta)

    for key in sorted(set(before_idx) | set(after_idx)):
        kind, identity = key
        b = before_idx.get(key)
        a = after_idx.get(key)
        present_in = present_in_for.get(key, absent)
        lasted = any(present_in.values())

        if b is not None and a is not None:
            changes = _diff_attributes(b.attributes, a.attributes)
            if changes:
                _record(
                    Delta(
                        change="modified",
                        kind=kind,
                        identity=identity,
                        label=a.label,
                        first_seen_phase=phase,
                        present_in=present_in,
                        attributes=a.attributes,
                        attribute_changes=changes,
                        related_events=events_for(kind, identity),
                    )
                )
            continue

        # A presence flip at this boundary. Record it only when the end-snapshot
        # pass genuinely could not have seen it: a plug-and-vanish that never
        # settled (`not lasted`), or an established item that briefly flipped
        # mid-phase (the main comparison logged no appear/disappear for it).
        if lasted and key in main_presence_changes:
            continue

        if a is not None:  # absent -> present
            _record(
                Delta(
                    change="appeared",
                    kind=kind,
                    identity=identity,
                    label=a.label,
                    first_seen_phase=phase,
                    present_in=present_in,
                    reverted_after_disconnect=True,
                    transient=not lasted,
                    attributes=a.attributes,
                    related_events=events_for(kind, identity),
                )
            )
        elif b is not None:  # present -> absent
            _record(
                Delta(
                    change="disappeared",
                    kind=kind,
                    identity=identity,
                    label=b.label,
                    first_seen_phase=phase,
                    present_in=present_in,
                    reverted_after_disconnect=True,
                    transient=not lasted,
                    attributes=b.attributes,
                    related_events=events_for(kind, identity),
                )
            )


def _transient_deltas(
    existing: list[Delta],
    seen_in_snapshots: dict[tuple[str, str], Observation],
    events_by_key: dict[tuple[str, str], list[ProbeEvent]],
    *,
    phase: str,
) -> list[Delta]:
    """Devices ADDED and REMOVED within ``phase`` that never landed in an
    end-of-phase snapshot - a genuine plug-and-vanish.

    A device that was only added (and stays, or is removed in a later phase) is
    not transient; if a snapshot probe missed it that is a keying problem, not a
    short-lived payload, and flagging it just adds noise.
    """

    known = {(d.kind, d.identity) for d in existing}

    out: list[Delta] = []
    for key, key_events in events_by_key.items():
        if key in known or key in seen_in_snapshots:
            continue
        if not any(e.action in _ADD_ACTIONS for e in key_events):
            continue
        if not any(e.action in _REMOVE_ACTIONS for e in key_events):
            continue
        known.add(key)
        kind, identity = key
        first_add = next(e for e in key_events if e.action in _ADD_ACTIONS)
        out.append(
            Delta(
                change="appeared",
                kind=kind,
                identity=identity,
                label=first_add.label,
                first_seen_phase=phase,
                present_in={
                    PHASE_BASELINE: False,
                    PHASE_TEST: False,
                    PHASE_POST_TEST: False,
                },
                reverted_after_disconnect=True,  # add + remove seen within one phase
                transient=True,
                attributes=first_add.attributes,
                related_events=key_events,
            )
        )
    return out


def build_summary(
    phases: dict[str, PhaseObservation],
    deltas: list[Delta],
    findings: list[object],
) -> dict:
    from cableprobe.models import Finding  # local import to avoid cycle at top

    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    by_severity: dict[str, int] = {}
    highest = "info"
    for finding in findings:
        assert isinstance(finding, Finding)
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        if severity_rank.get(finding.severity, 0) >= severity_rank.get(highest, 0):
            highest = finding.severity

    cable_correlated = [d for d in deltas if d.first_seen_phase == PHASE_TEST]
    persisted = [
        d
        for d in cable_correlated
        if d.change == "appeared"
        and d.reverted_after_disconnect is False
        and d.kind in PERSISTENCE_KINDS
    ]

    snapshot_error_count = sum(
        len(snap.errors)
        for p in phases.values()
        for snap in (p.start_snapshot, p.end_snapshot)
    )

    return {
        "phase_observation_counts": {
            name: len(p.end_snapshot.observations) for name, p in phases.items()
        },
        "phase_event_counts": {name: len(p.events) for name, p in phases.items()},
        "events_dropped": sum(p.events_dropped for p in phases.values()),
        "snapshot_error_count": snapshot_error_count,
        "coverage": "partial" if snapshot_error_count else "full",
        "delta_count": len(deltas),
        "deltas_by_change": _count_by(deltas, lambda d: d.change),
        "deltas_by_kind": _count_by(deltas, lambda d: d.kind),
        "cable_correlated_change_count": len(cable_correlated),
        "persisted_after_disconnect_count": len(persisted),
        "finding_count": len(findings),
        "findings_by_severity": by_severity,
        "highest_severity": highest if findings else None,
    }


def _count_by(items, keyfn) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        k = keyfn(item)
        out[k] = out.get(k, 0) + 1
    return out
