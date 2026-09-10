# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Shared test fixtures and builders."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cableprobe.models import (
    PHASE_BASELINE,
    PHASE_POST_TEST,
    PHASE_TEST,
    Observation,
    PhaseObservation,
    ProbeEvent,
    SystemSnapshot,
)

_T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def obs(kind: str, identity: str, label: str | None = None, **attributes) -> Observation:
    return Observation(
        kind=kind,
        identity=identity,
        label=label or f"{kind} {identity}",
        attributes=attributes,
    )


def snapshot(observations: list[Observation], *, at: datetime | None = None) -> SystemSnapshot:
    return SystemSnapshot(timestamp=at or _T0, observations=list(observations))


def phase(
    name: str,
    start_obs: list[Observation],
    end_obs: list[Observation] | None = None,
    *,
    events: list[ProbeEvent] | None = None,
    offset_minutes: int = 0,
) -> PhaseObservation:
    started = _T0 + timedelta(minutes=offset_minutes)
    ended = started + timedelta(minutes=1)
    return PhaseObservation(
        phase=name,
        started_at=started,
        ended_at=ended,
        start_snapshot=snapshot(start_obs, at=started),
        end_snapshot=snapshot(end_obs if end_obs is not None else start_obs, at=ended),
        events=events or [],
    )


def event(action: str, kind: str, identity: str, label: str | None = None, **attributes) -> ProbeEvent:
    return ProbeEvent(
        timestamp=_T0,
        probe="udev_monitor",
        action=action,
        kind=kind,
        identity=identity,
        label=label or identity,
        attributes=attributes,
    )


def make_phases(baseline_end, test_end, post_end, *, test_events=None, post_events=None):
    return {
        PHASE_BASELINE: phase(PHASE_BASELINE, baseline_end, offset_minutes=0),
        PHASE_TEST: phase(
            PHASE_TEST, test_end, test_end, events=test_events or [], offset_minutes=2
        ),
        PHASE_POST_TEST: phase(
            PHASE_POST_TEST, post_end, post_end, events=post_events or [], offset_minutes=4
        ),
    }


@pytest.fixture
def phase_builder():
    return make_phases


@pytest.fixture
def t0() -> datetime:
    return _T0
