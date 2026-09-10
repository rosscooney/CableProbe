# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Session orchestration: run the three phases and assemble the report."""

from __future__ import annotations

import asyncio
import threading
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
from cableprobe.rules import _SEVERITY_RANK, RuleSet, consolidate
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


def _snapshot_error_summary(phases: dict[str, PhaseObservation]) -> dict[str, str]:
    """Per-probe: ``"<n>/<total> snapshots failed - <last message>"``.

    Errors are recorded on each snapshot as ``"<probe>: <exception>"``. A probe
    in here started fine but then failed to observe, so its part of the picture
    is missing and a clean result should not be trusted.
    """

    fails: dict[str, int] = {}
    last_msg: dict[str, str] = {}
    total = 0
    for phase in phases.values():
        for snap in (phase.start_snapshot, phase.end_snapshot):
            total += 1
            for err in snap.errors:
                name, _, msg = err.partition(":")
                name = name.strip()
                fails[name] = fails.get(name, 0) + 1
                # collapse multi-line tool usage blurbs to one line
                last_msg[name] = " ".join(msg.split()) or "unknown error"
    return {
        name: f"{n}/{total} snapshots failed - {last_msg[name]}"
        for name, n in sorted(fails.items())
    }


def _incomplete_monitoring(phases: dict[str, PhaseObservation]) -> list[str]:
    """Observations at *any* snapshot this session that a probe flagged as a
    standing blind spot - an unreadable persistence file, a truncated kernel
    log, ... (``monitoring_incomplete`` / ``fingerprint_incomplete``)."""

    out: set[str] = set()
    for phase in phases.values():
        for snap in (phase.start_snapshot, phase.end_snapshot):
            for obs in snap.observations:
                if obs.attributes.get("monitoring_incomplete") or obs.attributes.get(
                    "fingerprint_incomplete"
                ):
                    out.add(str(obs.attributes.get("path") or obs.label or obs.identity))
    return sorted(out)


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


#: A single probe snapshot should be quick (sysfs reads, one or two subprocess
#: calls that carry their own 15s timeout). Past this it is wedged - a hung
#: file read, a stuck tool - and the phase must not wait on it forever.
_SNAPSHOT_TIMEOUT = 45.0

#: Per-phase event budget. A normal session sees well under a hundred events; a
#: flood past this is an event storm (rapid re-plug, a chatty gadget) and the
#: rest are counted, not kept, so one session can't produce an unbounded report.
_MAX_PHASE_EVENTS = 10_000


def _swallow_abandoned(fut: asyncio.Future) -> None:
    """Retrieve the eventual result/exception of a timed-out snapshot future so
    asyncio does not log 'exception was never retrieved' for it."""

    def _drain(f: asyncio.Future) -> None:
        if not f.cancelled():
            try:
                f.exception()
            except asyncio.CancelledError:  # pragma: no cover
                pass

    fut.add_done_callback(_drain)


async def _snapshot_one(
    probe: Probe, quarantine: set[str]
) -> tuple[list[Observation], list[str]]:
    # Run the (blocking) snapshot on a *daemon* thread we start ourselves, not
    # asyncio.to_thread's shared executor: if the probe wedges, a daemon thread
    # does not block interpreter exit, and we never join it - so a stuck probe
    # can no longer delay the report or hang the process at shutdown.
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()

    def _worker() -> None:
        try:
            result = _safe_snapshot(probe)
            payload = (fut.set_result, result)
        except BaseException as exc:  # noqa: BLE001  # pragma: no cover
            payload = (fut.set_exception, exc)
        try:
            loop.call_soon_threadsafe(_settle, *payload)
        except RuntimeError:  # pragma: no cover - loop already closed; nothing to deliver
            pass

    def _settle(setter, value) -> None:
        if not fut.done():  # the await may have already timed out
            setter(value)

    threading.Thread(
        target=_worker, name=f"cableprobe-snapshot-{probe.name}", daemon=True
    ).start()

    try:
        return await asyncio.wait_for(asyncio.shield(fut), _SNAPSHOT_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError):
        _swallow_abandoned(fut)
        # Stop scheduling this probe: another slow call each phase would just
        # leak another stuck thread.
        quarantine.add(probe.name)
        log.warning(
            "probe %s snapshot exceeded %.0fs - quarantined for the rest of the "
            "session (its worker thread is abandoned)",
            probe.name,
            _SNAPSHOT_TIMEOUT,
        )
        return [], [
            f"{probe.name}: snapshot timed out after {_SNAPSHOT_TIMEOUT:.0f}s "
            "(quarantined)"
        ]


async def _capture(probes: list[Probe], quarantine: set[str]) -> SystemSnapshot:
    # Probe snapshots block on subprocesses / sysfs; run them off the event loop
    # so enabled probes are actually captured concurrently, each with a deadline.
    already = set(quarantine)  # quarantined before this capture (not by it)
    to_run = [p for p in probes if p.name not in already]
    results = await asyncio.gather(*(_snapshot_one(p, quarantine) for p in to_run))
    observations: list[Observation] = []
    errors: list[str] = [
        f"{p.name}: skipped (quarantined after an earlier snapshot timeout)"
        for p in probes
        if p.name in already
    ]
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
    quarantine: set[str] | None = None,
) -> PhaseObservation:
    quarantine = quarantine if quarantine is not None else set()
    started_at = utcnow()
    start_snapshot = await _capture(probes, quarantine)

    events: list[ProbeEvent] = []
    dropped = 0

    def _collect(new: list[ProbeEvent]) -> None:
        nonlocal dropped
        room = _MAX_PHASE_EVENTS - len(events)
        if room > 0:
            events.extend(new[:room])
        if len(new) > max(room, 0):
            dropped += len(new) - max(room, 0)

    # Events queued during the lead-in - the operator prompt, the plug/unplug
    # action itself, the start-snapshot capture - are this phase's opening
    # moments. Keep them (they used to be discarded, losing the connect uevent).
    _collect(_drain(probes))

    elapsed = 0.0
    while elapsed < duration:
        step = min(interval, duration - elapsed)
        await sleep(step)
        elapsed += step
        # Drain any events probes queued during this interval, and advance the
        # progress display. Snapshots are only captured at the phase boundaries;
        # intra-phase sampling is not consumed by analyse() yet (see issue #1:
        # in-phase transient detection).
        _collect(_drain(probes))
        if on_tick is not None:
            on_tick(phase, elapsed, duration)

    end_snapshot = await _capture(probes, quarantine)
    _collect(_drain(probes))

    # events a probe discarded itself (its own buffer overflowed) also count
    for probe in probes:
        try:
            dropped += probe.dropped_events()
        except Exception as exc:  # noqa: BLE001  # pragma: no cover
            log.debug("probe %s dropped_events failed: %s", probe.name, exc)

    if dropped:
        log.warning(
            "phase %s: event budget (%d) exceeded, dropped %d event(s)",
            phase,
            _MAX_PHASE_EVENTS,
            dropped,
        )

    return PhaseObservation(
        phase=phase,
        started_at=started_at,
        ended_at=utcnow(),
        start_snapshot=start_snapshot,
        end_snapshot=end_snapshot,
        events=events,
        events_dropped=dropped,
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

    quarantined_probes: set[str] = set()  # probes dropped after a snapshot timeout
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
                quarantine=quarantined_probes,
                sleep=sleep,
                on_tick=on_tick,
            )
    finally:
        await _stop_probes(probes)

    deltas = analyse(phases)
    # Allowlist per raw (per-device) finding *before* consolidation, so one
    # trusted device cannot pull down a finding that also concerns an untrusted
    # one. Implant findings are already one-per-device; keep them unconsolidated.
    raw = ruleset.evaluate_raw(deltas)
    implant_findings = list(implants.check(deltas)) if implants is not None else []
    if allowlist is not None:
        raw = apply_allowlist(raw, deltas, allowlist)
        implant_findings = apply_allowlist(implant_findings, deltas, allowlist)
    findings = consolidate(raw) + implant_findings
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True)
    summary = build_summary(phases, deltas, findings)

    # Coverage is "partial" if *anything* left a gap this session: a probe that
    # failed to start, a probe that errored while observing, an event storm that
    # overran a buffer, or a probe that flagged its own data as incomplete
    # (unreadable persistence file, truncated kernel log, ...).
    start_failures = [w for w in warnings if "failed to start" in w]
    incomplete = _incomplete_monitoring(phases)
    if (
        start_failures
        or summary.get("snapshot_error_count")
        or summary.get("events_dropped")
        or incomplete
    ):
        summary["coverage"] = "partial"
    summary["coverage_gaps"] = {
        "probes_failed_to_start": [w.split(":", 1)[0].strip() for w in start_failures],
        "probes_errored": sorted(_snapshot_error_summary(phases)),
        "events_dropped": summary.get("events_dropped", 0),
        "incomplete_data": incomplete,
    }

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
        probe_snapshot_errors=_snapshot_error_summary(phases),
    )

    return SessionReport(
        metadata=metadata,
        phases=phases,
        deltas=deltas,
        findings=findings,
        summary=summary,
    )
