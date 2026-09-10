# Copyright (c) 2026-present Stable State Consulting Ltd
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
    KIND_PROCESS,
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
from cableprobe.knowledge import Allowlist, ImplantList, apply_allowlist
from cableprobe.probes import Probe, build_probes
from cableprobe.redact import MASK as _REDACT_MASK
from cableprobe.rules import _SEVERITY_RANK, RuleSet
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


def _cmdline_secret_was_masked(phases: dict[str, PhaseObservation]) -> bool:
    """True if any captured process command line had a value redacted."""

    for phase in phases.values():
        for snap in (phase.start_snapshot, phase.end_snapshot):
            for obs in snap.observations:
                if obs.kind == KIND_PROCESS:
                    cmdline = obs.attributes.get("cmdline")
                    if isinstance(cmdline, str) and _REDACT_MASK in cmdline:
                        return True
    return False


def _safe_snapshot(probe: Probe) -> tuple[list[Observation], list[str]]:
    try:
        return probe.snapshot(), []
    except Exception as exc:  # noqa: BLE001
        log.warning("probe %s snapshot failed: %s", probe.name, exc)
        return [], [f"{probe.name}: {exc}"]


async def _capture(probes: list[Probe]) -> SystemSnapshot:
    # Probe snapshots block on subprocesses / sysfs; run them off the event loop
    # so enabled probes are actually captured concurrently.
    results = await asyncio.gather(
        *(asyncio.to_thread(_safe_snapshot, p) for p in probes)
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
    elapsed = 0.0
    while elapsed < duration:
        step = min(interval, duration - elapsed)
        await sleep(step)
        elapsed += step
        # Drain any events probes queued during this interval, and advance the
        # progress display. Snapshots are only captured at the phase boundaries;
        # intra-phase sampling is not consumed by analyse() yet (see issue #1:
        # in-phase transient detection).
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
    implants: ImplantList | None = None,
    allowlist: Allowlist | None = None,
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
    findings = list(ruleset.evaluate(deltas))
    if implants is not None:
        findings.extend(implants.check(deltas))
    if allowlist is not None:
        findings = apply_allowlist(findings, deltas, allowlist)
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True)
    summary = build_summary(phases, deltas, findings)

    # Only flag the report when redaction actually masked something in a
    # captured command line - that is when "review before sharing" is
    # actionable. Command-line capture on its own is documented, not alarming.
    if config.probes.capture_process_cmdline and _cmdline_secret_was_masked(phases):
        warnings.append(
            "process: a captured command line contained a value that looked like "
            f"a secret; it was masked ({_REDACT_MASK}). Check the rest of the "
            "report before sharing it."
        )

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
