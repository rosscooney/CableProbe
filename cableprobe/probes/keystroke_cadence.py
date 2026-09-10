# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Keystroke-cadence analysis for injection detection.

A BadUSB implant that appears as a keyboard has to *type*, and it types unlike a
human: either far faster than anyone can (hundreds of characters per second) or
with machine-perfect regularity (every keystroke exactly N milliseconds apart).
This probe watches the evdev input devices for key-press events and, for each
device, reports timing statistics and a heuristic verdict.

**Privacy:** only the *timing* of key-down events is recorded. The key `code`
field of every event is discarded before anything is stored, so this probe
never learns which keys were pressed. It can be disabled entirely with
``probes.capture_keystroke_timing: false``.

Reading ``/dev/input/event*`` needs root (or membership of the ``input``
group); without it the probe reports itself unavailable.
"""

from __future__ import annotations

import glob
import os
import select
import struct
import threading
import time
from collections import deque
from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_KEYSTROKE_TIMING, Observation
from cableprobe.probes.base import Probe, ProbeAvailability

log = get_logger("probe.keystroke_cadence")

DEV_INPUT_GLOB = "/dev/input/event*"
SYS_CLASS_INPUT = "/sys/class/input"

# struct input_event = { struct timeval time; __u16 type; __u16 code; __s32 value; }
# Native layout matches the running kernel's word size (64-bit on RPi OS today).
NATIVE_EVENT_FORMAT = "llHHi"

EV_KEY = 0x01
KEY_DOWN = 1  # value: 0 = release, 1 = press, 2 = autorepeat

#: Heuristic thresholds.
SUPERHUMAN_MEAN_INTERVAL_MS = 40.0   # sustained <40 ms/key => >25 keys/s
ROBOTIC_CV_MAX = 0.12                # coefficient of variation below this = machine
MIN_KEYS_FOR_VERDICT = 8
#: Cap on retained timestamps per device (a fast implant could otherwise flood).
MAX_TIMESTAMPS = 20000


def parse_key_down_timestamps(
    raw: bytes, *, event_format: str = NATIVE_EVENT_FORMAT
) -> list[float]:
    """Extract key-press timestamps (seconds, float) from raw ``input_event`` bytes.

    Only ``EV_KEY`` events with ``value == 1`` (a press) are kept, and only their
    timestamps -- the key ``code`` is never returned.
    """

    size = struct.calcsize(event_format)
    out: list[float] = []
    for offset in range(0, len(raw) - size + 1, size):
        sec, usec, etype, _code, value = struct.unpack(
            event_format, raw[offset : offset + size]
        )
        if etype == EV_KEY and value == KEY_DOWN:
            out.append(sec + usec / 1_000_000)
    return out


def _window_verdict(intervals: list[float]) -> tuple[bool, bool, float, float]:
    """(superhuman, robotic, mean_ms, cv) for one run of intervals."""

    mean = sum(intervals) / len(intervals)
    stdev = (sum((x - mean) ** 2 for x in intervals) / len(intervals)) ** 0.5
    cv = (stdev / mean) if mean > 0 else 0.0
    superhuman = mean * 1000 < SUPERHUMAN_MEAN_INTERVAL_MS
    robotic = cv < ROBOTIC_CV_MAX
    return superhuman, robotic, mean * 1000, cv


def summarise_cadence(timestamps: list[float]) -> dict:
    """Turn a list of key-press timestamps into timing stats + a verdict.

    The verdict is taken from the *worst* sliding window of
    ``MIN_KEYS_FOR_VERDICT`` consecutive presses, not the whole-session average:
    a fast injected burst surrounded by slow human typing and long pauses would
    otherwise be diluted below the thresholds.
    """

    ts = sorted(timestamps)
    n = len(ts)
    summary: dict = {"keystrokes": n}
    if n < 2:
        summary.update(
            {"superhuman_speed": False, "robotically_regular": False, "looks_injected": False}
        )
        return summary

    intervals = [b - a for a, b in zip(ts, ts[1:]) if b >= a]
    duration = ts[-1] - ts[0]
    overall_mean = sum(intervals) / len(intervals)

    win = max(MIN_KEYS_FOR_VERDICT - 1, 1)  # intervals per window
    superhuman = robotic = False
    burst_mean_ms = burst_cv = None
    if len(intervals) >= win:
        for i in range(len(intervals) - win + 1):
            s, r, m_ms, c = _window_verdict(intervals[i : i + win])
            if s:
                superhuman = True
                burst_mean_ms = m_ms if burst_mean_ms is None else min(burst_mean_ms, m_ms)
            if r:
                robotic = True
                burst_cv = c if burst_cv is None else min(burst_cv, c)

    summary.update(
        {
            "duration_s": round(duration, 3),
            "keys_per_second": round((n - 1) / duration, 1) if duration > 0 else None,
            "mean_interval_ms": round(overall_mean * 1000, 2),
            "burst_mean_interval_ms": round(burst_mean_ms, 2) if burst_mean_ms else None,
            "burst_coefficient_of_variation": round(burst_cv, 4) if burst_cv is not None else None,
            "min_interval_ms": round(min(intervals) * 1000, 2),
            "superhuman_speed": superhuman,
            "robotically_regular": robotic,
            "looks_injected": bool(superhuman or robotic),
        }
    )
    return summary


def _device_name(event_name: str, sys_root: str = SYS_CLASS_INPUT) -> str:
    try:
        return (
            Path(sys_root, event_name, "device", "name")
            .read_text(encoding="utf-8", errors="ignore")
            .strip()
        ) or event_name
    except OSError:
        return event_name


class KeystrokeCadenceProbe(Probe):
    name = "keystroke_cadence"
    description = "Key-press timing per input device; flags superhuman / robotic typing"

    def __init__(self, config, session_start: float) -> None:
        super().__init__(config, session_start)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._timestamps: dict[str, deque[float]] = {}
        self._enabled = getattr(config.probes, "capture_keystroke_timing", True)

    def availability(self) -> ProbeAvailability:
        if not self._enabled:
            return ProbeAvailability(
                ok=False, detail="disabled (probes.capture_keystroke_timing = false)"
            )
        nodes = glob.glob(DEV_INPUT_GLOB)
        if not nodes:
            return ProbeAvailability(ok=False, detail="no /dev/input/event* nodes")
        if not any(os.access(node, os.R_OK) for node in nodes):
            return ProbeAvailability(
                ok=False, detail="/dev/input/event* not readable (needs root / input group)"
            )
        return ProbeAvailability(ok=True, detail=f"{len(nodes)} input node(s)")

    async def start(self) -> None:
        if not self._enabled:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="cableprobe-keystroke-cadence", daemon=True
        )
        self._thread.start()

    async def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=3.0)
        self._thread = None

    #: After a read fails, wait this long before re-opening the same device -
    #: so a wedged device cannot be reopened in a tight loop.
    _QUARANTINE_SECONDS = 5.0

    def _run(self) -> None:  # pragma: no cover - needs real evdev
        open_fds: dict[int, tuple[str, int]] = {}  # fd -> (node path, st_rdev)
        open_rdev: set[int] = set()  # device numbers already open (survives re-plug)
        quarantine: dict[int, float] = {}  # st_rdev -> monotonic time to retry

        def _drop(fd: int, *, quarantine_it: bool = False) -> None:
            entry = open_fds.pop(fd, None)
            if entry is not None:
                open_rdev.discard(entry[1])
                if quarantine_it:
                    quarantine[entry[1]] = time.monotonic() + self._QUARANTINE_SECONDS
            try:
                os.close(fd)
            except OSError:
                pass

        try:
            while not self._stop.is_set():
                now = time.monotonic()
                quarantine = {r: t for r, t in quarantine.items() if t > now}
                for node in glob.glob(DEV_INPUT_GLOB):
                    try:
                        rdev = os.stat(node).st_rdev
                    except OSError:
                        continue
                    if rdev in open_rdev or rdev in quarantine:
                        continue
                    try:
                        fd = os.open(node, os.O_RDONLY | os.O_NONBLOCK)
                    except OSError:
                        continue
                    open_fds[fd] = (node, rdev)
                    open_rdev.add(rdev)

                if not open_fds:
                    time.sleep(0.5)
                    continue

                readable, _, errored = select.select(
                    list(open_fds), [], list(open_fds), 0.5
                )
                for fd in errored:
                    _drop(fd, quarantine_it=True)
                for fd in readable:
                    if fd not in open_fds:
                        continue
                    try:
                        raw = os.read(fd, 65536)
                    except OSError:
                        _drop(fd, quarantine_it=True)  # EIO - stop spinning on it
                        continue
                    if not raw:  # EOF - the device disconnected
                        _drop(fd)
                        continue
                    stamps = parse_key_down_timestamps(raw)
                    if not stamps:
                        continue
                    name = Path(open_fds[fd][0]).name
                    with self._lock:
                        bucket = self._timestamps.setdefault(
                            name, deque(maxlen=MAX_TIMESTAMPS)
                        )
                        bucket.extend(stamps)
        finally:
            for fd in list(open_fds):
                _drop(fd)

    def snapshot(self) -> list[Observation]:
        with self._lock:
            snapshot = {name: list(stamps) for name, stamps in self._timestamps.items()}

        observations: list[Observation] = []
        for event_name, stamps in snapshot.items():
            if not stamps:
                continue
            summary = summarise_cadence(stamps)
            human_name = _device_name(event_name)
            observations.append(
                Observation(
                    kind=KIND_KEYSTROKE_TIMING,
                    identity=f"kbdtiming:{event_name}",
                    label=(
                        f"key-press timing for {human_name}: "
                        f"{summary['keystrokes']} press(es)"
                        + (" — LOOKS INJECTED" if summary.get("looks_injected") else "")
                    ),
                    attributes={
                        "device_name": human_name,
                        "event_node": event_name,
                        **summary,
                    },
                )
            )
        return observations
