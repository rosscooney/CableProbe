# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Phase comparison: turn three PhaseObservations into a list of Deltas."""

from __future__ import annotations

from cableprobe.logging_config import get_logger
from cableprobe.models import (
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


def _events_for(identity: str, kind: str, events: list[ProbeEvent]) -> list[ProbeEvent]:
    return [e for e in events if e.identity == identity and e.kind == kind]


def analyse(phases: dict[str, PhaseObservation]) -> list[Delta]:
    """Compare baseline / test / post-test end snapshots and phase events."""

    baseline = phases[PHASE_BASELINE].end_snapshot.index()
    test = phases[PHASE_TEST].end_snapshot.index()
    post = phases[PHASE_POST_TEST].end_snapshot.index()

    test_events = phases[PHASE_TEST].events
    post_events = phases[PHASE_POST_TEST].events

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
                    related_events=_events_for(identity, kind, test_events),
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
                    related_events=_events_for(identity, kind, post_events),
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
                    related_events=_events_for(identity, kind, test_events),
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
                        related_events=_events_for(identity, kind, test_events),
                    )
                )

    deltas.extend(_transient_deltas(deltas, baseline, test_events))
    return deltas


def _transient_deltas(
    existing: list[Delta],
    baseline: dict[tuple[str, str], Observation],
    test_events: list[ProbeEvent],
) -> list[Delta]:
    """Devices that were both ADDED and REMOVED during TEST and never landed in
    an end-of-phase snapshot - a genuine plug-and-vanish.

    A device that was only added (and stays, or is removed later in post-test)
    is not transient; if a snapshot probe missed it that is a keying problem,
    not a short-lived payload, and flagging it just adds noise.
    """

    known = {(d.kind, d.identity) for d in existing}
    removed_keys: set[tuple[str, str]] = set()
    events_by_key: dict[tuple[str, str], list[ProbeEvent]] = {}
    for event in test_events:
        key = (event.kind, event.identity)
        events_by_key.setdefault(key, []).append(event)
        if event.action in _REMOVE_ACTIONS:
            removed_keys.add(key)

    out: list[Delta] = []
    for key, events in events_by_key.items():
        if key in known or key in baseline:
            continue
        if not any(e.action in _ADD_ACTIONS for e in events):
            continue
        if key not in removed_keys:
            continue
        known.add(key)
        kind, identity = key
        first_add = next(e for e in events if e.action in _ADD_ACTIONS)
        out.append(
            Delta(
                change="appeared",
                kind=kind,
                identity=identity,
                label=first_add.label,
                first_seen_phase=PHASE_TEST,
                present_in={
                    PHASE_BASELINE: False,
                    PHASE_TEST: False,
                    PHASE_POST_TEST: False,
                },
                reverted_after_disconnect=True,  # add + remove seen within TEST
                transient=True,
                attributes=first_add.attributes,
                related_events=events,
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

    return {
        "phase_observation_counts": {
            name: len(p.end_snapshot.observations) for name, p in phases.items()
        },
        "phase_event_counts": {name: len(p.events) for name, p in phases.items()},
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
