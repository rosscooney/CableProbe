# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Session orchestration: run the three phases and assemble the report."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

from cableprobe import __version__
from cableprobe.analysis import analyse, build_summary
from cableprobe.config import Config
from cableprobe.logging_config import get_logger
from cableprobe.models import (
    PHASE_BASELINE,
    PHASE_ORDER,
    PHASE_POST_TEST,
    PHASE_TEST,
    Observation,
    PhaseObservation,
    ProbeEvent,
    SessionMetadata,
    SessionReport,
    SystemSnapshot,
    utcnow,
)
from cableprobe.probes import Probe, build_probes
from cableprobe.rules import RuleSet
from cableprobe.system_info import collect_host_info

log = get_logger("session")

# prompt_fn(phase_name, human_message) -> awaitable/None. Injected for tests.
PromptFn = Callable[[str, str], Awaitable[None] | None]

_PHASE_PROMPTS = {
    PHASE_BASELINE: (
        "BASELINE PHASE\n"
        "Make sure the UNKNOWN cable is DISCONNECTED and nothing else is being "
        "plugged or unplugged. CableProbe will observe the system as-is.",
    ),
    PHASE_TEST: (
        "TEST PHASE\n"
        "Connect / power the UNKNOWN cable now (both ends as intended for the "
        "device under test). Do not touch anything else.",
    ),
    PHASE_POST_TEST: (
        "POST-TEST PHASE\n"
        "Disconnect the UNKNOWN cable now. CableProbe will keep observing to see "
        "whether everything returns to the baseline state.",
    ),
}


async def _maybe_await(value: Awaitable[None] | None) -> None:
    if asyncio.iscoroutine(value):
        await value


def _safe_snapshot(probe: Probe) -> tuple[list[Observation], list[str]]:
    try:
        return probe.snapshot(), []
    except Exception as exc:  # noqa: BLE001
        log.warning("probe %s snapshot failed: %s", probe.name, exc)
        return [], [f"{probe.name}: {exc}"]


async def _capture(probes: list[Probe], *, periodic: bool = False) -> SystemSnapshot:
    selected = [
        p for p in probes if not periodic or getattr(p, "samples_periodically", True)
    ]
    # Probe snapshots block on subprocesses / sysfs; run them off the event loop
    # so enabled probes are actually captured concurrently.
    results = await asyncio.gather(
        *(asyncio.to_thread(_safe_snapshot, p) for p in selected)
    )
    observations: list[Observation] = []
    errors: list[str] = []
    for obs, errs in results:
        observations.extend(obs)
        errors.extend(errs)
    return SystemSnapshot(timestamp=utcnow(), observations=observations, errors=errors)


def _drain(probes: list[Probe]) -> list[ProbeEvent]:
    events: list[ProbeEvent] = []
    for probe in probes:
        try:
            events.extend(probe.drain_events())
        except Exception as exc:  # noqa: BLE001  # pragma: no cover
            log.debug("probe %s drain_events failed: %s", probe.name, exc)
    return events


async def _observe_phase(
    probes: list[Probe],
    phase: str,
    duration: float,
    interval: float,
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    on_tick: Callable[[str, float, float], None] | None = None,
) -> PhaseObservation:
    started_at = utcnow()
    start_snapshot = await _capture(probes)
    _drain(probes)  # reset: events from here on belong to this phase

    events: list[ProbeEvent] = []
    samples: list[SystemSnapshot] = []
    elapsed = 0.0
    while elapsed < duration:
        step = min(interval, duration - elapsed)
        await sleep(step)
        elapsed += step
        samples.append(await _capture(probes, periodic=True))
        events.extend(_drain(probes))
        if on_tick is not None:
            on_tick(phase, elapsed, duration)

    end_snapshot = await _capture(probes)
    events.extend(_drain(probes))

    return PhaseObservation(
        phase=phase,
        started_at=started_at,
        ended_at=utcnow(),
        start_snapshot=start_snapshot,
        end_snapshot=end_snapshot,
        samples=samples,
        events=events,
    )


async def _start_probes(
    probes: list[Probe],
) -> tuple[list[Probe], list[str], list[str]]:
    """Start the probes that can run on this host.

    Returns ``(active_probes, unavailable_notes, warnings)``. A probe whose
    ``availability()`` is not ``ok`` is dropped (it would only contribute empty
    snapshots or per-tick errors); that is an expected condition on hosts that
    do not expose a given interface, so it is reported separately from real
    failures.
    """

    active: list[Probe] = []
    unavailable: list[str] = []
    warnings: list[str] = []
    for probe in probes:
        availability = probe.availability()
        if not availability.ok:
            msg = f"{probe.name}: {availability.detail}"
            log.info("probe %s unavailable on this host: %s", probe.name, availability.detail)
            unavailable.append(msg)
            continue
        try:
            await probe.start()
        except Exception as exc:  # noqa: BLE001
            msg = f"{probe.name}: failed to start ({exc})"
            log.warning(msg)
            warnings.append(msg)
            continue
        active.append(probe)
    return active, unavailable, warnings


async def _stop_probes(probes: list[Probe]) -> None:
    for probe in probes:
        try:
            await probe.stop()
        except Exception as exc:  # noqa: BLE001  # pragma: no cover
            log.debug("probe %s stop failed: %s", probe.name, exc)


async def run_session(
    config: Config,
    ruleset: RuleSet,
    *,
    session_name: str,
    prompt_fn: PromptFn | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    on_tick: Callable[[str, float, float], None] | None = None,
) -> SessionReport:
    """Run baseline / test / post-test and return a structured report."""

    session_start = time.time()
    started_at = utcnow()
    configured = build_probes(config, session_start)
    if not configured:
        raise RuntimeError("no probes enabled - nothing to observe")

    log.info(
        "starting session %r with probes: %s",
        session_name,
        [p.name for p in configured],
    )
    probes, unavailable, warnings = await _start_probes(configured)
    if not probes:
        raise RuntimeError(
            "no enabled probe can run on this host - nothing to observe "
            f"(unavailable: {'; '.join(unavailable) or 'none'})"
        )

    phases: dict[str, PhaseObservation] = {}
    durations = {
        PHASE_BASELINE: config.session.baseline_seconds,
        PHASE_TEST: config.session.test_seconds,
        PHASE_POST_TEST: config.session.post_test_seconds,
    }

    try:
        _drain(probes)
        for phase in PHASE_ORDER:
            (message,) = _PHASE_PROMPTS[phase]
            if prompt_fn is not None:
                await _maybe_await(prompt_fn(phase, message))
            log.info("phase %s: observing for %ss", phase, durations[phase])
            phases[phase] = await _observe_phase(
                probes,
                phase,
                float(durations[phase]),
                config.session.sample_interval_seconds,
                sleep=sleep,
                on_tick=on_tick,
            )
    finally:
        await _stop_probes(probes)

    deltas = analyse(phases)
    findings = ruleset.evaluate(deltas)
    summary = build_summary(phases, deltas, findings)

    metadata = SessionMetadata(
        session_name=session_name,
        cableprobe_version=__version__,
        started_at=started_at,
        ended_at=utcnow(),
        interactive=config.session.interactive,
        host=collect_host_info(),
        config=config.as_metadata(),
        probes_used=[p.name for p in probes],
        probes_unavailable=unavailable,
        probe_warnings=warnings,
    )

    return SessionReport(
        metadata=metadata,
        phases=phases,
        deltas=deltas,
        findings=findings,
        summary=summary,
    )
