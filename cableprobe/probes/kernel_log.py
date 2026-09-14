# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Kernel ring-buffer / journal capture, filtered to USB-relevant lines.

Captures kernel messages emitted since the session started and keeps the ones
matching a keyword list (USB enumeration, HID, CDC/RNDIS ethernet gadgets, hub
activity, descriptor-read errors, etc.).

The journal backend reads incrementally: the first ``snapshot()`` call
bootstraps with ``--since <session start>``; every one after that resumes from
a saved cursor (``--after-cursor``), so a long session does not re-fetch and
re-filter everything already seen on every phase-boundary snapshot. The probe
keeps the full, deduplicated set of matched messages across calls (``analyse()``
expects each snapshot's observation list to be the *cumulative* picture, not
just what is new), so ``snapshot()`` still returns everything matched so far
even though only the incremental slice was actually re-read. A cursor that
stops working mid-session (the journal was rotated or vacuumed) falls back to
a fresh ``--since`` read and is flagged as incomplete, rather than silently
losing whatever happened in between.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_KERNEL_MESSAGE, Observation
from cableprobe.probes.base import Probe, ProbeAvailability, have_tool, run_command

log = get_logger("probe.kernel")

# Lines that are worth surfacing on their own: things the structured probes do
# NOT already tell you - enumeration failures, electrical faults, and the
# network / serial *gadget* driver classes a hostile cable would bring up.
SIGNAL_KEYWORDS = [
    # USB network / serial / MBIM gadget classes
    "cdc_ether",
    "cdc_ncm",
    "cdc_mbim",
    "cdc_subset",
    "cdc_acm",
    "rndis",
    "usbnet",
    "ax88",
    "r8152",
    "r8153",
    "huawei_cdc_ncm",
    # enumeration failures / electrical problems
    "device descriptor read",
    "unable to enumerate",
    "cannot enumerate",
    "unable to get descriptor",
    "not accepting address",
    "device not accepting",
    "can't set config",
    "rejected 1 configuration",
    "string descriptor 0 read error",
    "over-current",
    "overcurrent",
    "ep0 in",
    "-71",
    "-110",
    "-32",
    # hubs (a hidden hub inside a cable)
    "USB hub found",
    "hub_port_",
]

# Everything above, plus the routine enumeration chatter ("New USB device
# found", "Product:", "input: X as ...", link-speed lines). Enabled with
# ``probes.kernel_log_verbose: true`` - useful for forensics, noisy by default
# because the ``usb`` / ``input`` / ``usb_descriptors`` probes already carry it.
VERBOSE_KEYWORDS = SIGNAL_KEYWORDS + [
    "usb",
    "hub",
    "hid",
    "input",
    "new full-speed",
    "new high-speed",
    "new low-speed",
    "new SuperSpeed",
]

#: Back-compat alias.
DEFAULT_KEYWORDS = SIGNAL_KEYWORDS

#: Hard cap on kernel-log lines pulled per snapshot. A session-storming device
#: (thousands of enumeration errors) must not make the report unbounded.
_MAX_KERNEL_LINES = 100_000

_LEADING_TIMESTAMP = re.compile(r"^\[\s*\d+\.\d+\]\s*")
_ISO_PREFIX = re.compile(r"^\S+\s+\S+\s+\S+\s+\S+\s+kernel:\s*", re.IGNORECASE)
_DIGITS = re.compile(r"\d+")


def _normalise(line: str) -> str:
    text = _LEADING_TIMESTAMP.sub("", line)
    text = _ISO_PREFIX.sub("", text)
    return _DIGITS.sub("#", text).strip()


def filter_kernel_lines(lines: list[str], keywords: list[str]) -> list[Observation]:
    lowered = [k.lower() for k in keywords]
    observations: list[Observation] = []
    seen: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if not any(k in low for k in lowered):
            continue
        norm = _normalise(stripped)
        identity = f"kmsg:{norm}"
        if identity in seen:
            continue
        seen.add(identity)
        observations.append(
            Observation(
                kind=KIND_KERNEL_MESSAGE,
                identity=identity,
                label=stripped[:400],
                attributes={"normalised": norm, "raw": stripped},
            )
        )
    return observations


#: journalctl trailer line --show-cursor appends after the last entry shown,
#: in every -o format: "-- cursor: s=...;i=...;b=...;m=...;t=...;x=...".
#: Documented, stable systemd/journalctl behaviour (since v233) - verify
#: against `journalctl --help` / the systemd.journal-fields(7) /
#: journalctl(1) man pages on the target host if this ever needs re-checking;
#: there is no journalctl available to test against in this dev environment.
_CURSOR_PREFIX = "-- cursor: "


class KernelLogProbe(Probe):
    name = "kernel_log"
    description = "USB-relevant kernel log / journal lines emitted during the session"

    def __init__(self, config, session_start: float) -> None:
        super().__init__(config, session_start)
        # journalctl only: resume from here next time instead of re-reading
        # everything since session start. None until the first successful read.
        self._cursor: str | None = None
        # The cumulative, deduplicated picture across every snapshot() call so
        # far - analyse() expects each call's result to be the full picture to
        # date, not just what changed, so this is what actually gets returned.
        # Keyed by identity: a later occurrence of the same kmsg naturally
        # coincides with what filter_kernel_lines() already dedupes on.
        self._seen: dict[str, Observation] = {}
        # Keyed by reason so distinct incompleteness causes (a size cap this
        # tick, a cursor invalidation a later one) both stay visible in the
        # cumulative result instead of one overwriting the other.
        self._incomplete: dict[str, Observation] = {}

    def _backend(self) -> str:
        configured = self.config.probes.kernel_log_backend
        if configured != "auto":
            return configured
        if have_tool("journalctl"):
            return "journalctl"
        if have_tool("dmesg"):
            return "dmesg"
        return "none"

    def availability(self) -> ProbeAvailability:
        backend = self._backend()
        if backend == "none":
            return ProbeAvailability(ok=False, detail="no journalctl or dmesg")
        return ProbeAvailability(ok=True, detail=f"using {backend}")

    def _keywords(self) -> list[str]:
        base = (
            VERBOSE_KEYWORDS
            if getattr(self.config.probes, "kernel_log_verbose", False)
            else SIGNAL_KEYWORDS
        )
        return base + list(self.config.probes.kernel_log_keywords)

    def _incomplete_marker(self, reason: str) -> Observation:
        return Observation(
            kind=KIND_KERNEL_MESSAGE,
            identity="kernel-log:incomplete",
            label=f"kernel log capture was incomplete ({reason})",
            attributes={"monitoring_incomplete": True, "reason": reason},
        )

    def _since_args(self) -> list[str]:
        since = datetime.fromtimestamp(self.session_start, tz=timezone.utc)
        return ["--since", since.astimezone().strftime("%Y-%m-%d %H:%M:%S")]

    def _split_cursor(self, out: str) -> tuple[list[str], str | None]:
        """Separate the ``--show-cursor`` trailer from the actual log lines.
        Returns ``(content_lines, new_cursor_or_None)``."""

        content: list[str] = []
        cursor: str | None = None
        for line in out.splitlines():
            if line.startswith(_CURSOR_PREFIX):
                cursor = line[len(_CURSOR_PREFIX) :].strip() or None
            else:
                content.append(line)
        return content, cursor

    def _read_journalctl(self) -> list[Observation]:
        lines_arg = str(_MAX_KERNEL_LINES)
        base_cmd = [
            "journalctl",
            "-k",
            "--no-pager",
            "-o",
            "short-iso",
            "--show-cursor",
            "--lines",
            lines_arg,  # hard cap on a session-storming host, even per-read
        ]
        range_args = ["--after-cursor", self._cursor] if self._cursor else self._since_args()
        code, out, err = run_command([*base_cmd, *range_args], timeout=20.0)

        extra: list[Observation] = []
        if code != 0 and self._cursor is not None:
            # the cursor may no longer be valid (the journal was rotated or
            # vacuumed since the last read) - fall back to a fresh --since
            # read rather than losing this probe for the rest of the session.
            # Entries between the last good read and now may have been lost,
            # so this is flagged, not silently absorbed.
            log.warning(
                "journalctl --after-cursor failed (%s); re-reading from session start",
                err.strip(),
            )
            self._cursor = None
            code, out, err = run_command([*base_cmd, *self._since_args()], timeout=20.0)
            extra.append(
                self._incomplete_marker(
                    "journal cursor was invalidated (rotation or vacuum); "
                    "re-read from session start - entries in between may "
                    "have been missed"
                )
            )
        if code != 0:
            raise RuntimeError(err.strip() or "journalctl failed")

        content, cursor = self._split_cursor(out)
        if cursor is not None:
            self._cursor = cursor
        else:
            # --show-cursor should always emit one on success; its absence
            # means the next read cannot safely resume incrementally
            extra.append(self._incomplete_marker("journalctl did not report a cursor"))

        obs = filter_kernel_lines(content, self._keywords())
        if getattr(out, "truncated", False) or len(content) >= _MAX_KERNEL_LINES:
            obs.append(self._incomplete_marker("output hit the size / line cap"))
        return obs + extra

    def _read_dmesg(self) -> list[Observation]:
        code, out, err = run_command(["dmesg", "--ctime"], timeout=20.0)
        if code != 0:
            code, out, err = run_command(["dmesg"], timeout=20.0)
        if code != 0:
            raise RuntimeError(err.strip() or "dmesg failed")
        obs = filter_kernel_lines(out.splitlines(), self._keywords())
        if getattr(out, "truncated", False):
            obs.append(self._incomplete_marker("dmesg output hit the size cap"))
        return obs

    def _merge(self, new_observations: list[Observation]) -> list[Observation]:
        """Fold ``new_observations`` into the running cumulative picture and
        return the full picture to date - not just what is new. dmesg always
        reports its whole current buffer, so this also fixes a latent gap
        there: a message that scrolled out of the kernel ring buffer between
        calls used to disappear from later snapshots even though kernel
        messages are documented (see analysis.PERSISTENCE_KINDS) to only ever
        accumulate for the rest of the session."""

        for observation in new_observations:
            bucket = self._incomplete if observation.attributes.get("monitoring_incomplete") else self._seen
            bucket[observation.identity] = observation
        return list(self._seen.values()) + list(self._incomplete.values())

    def snapshot(self) -> list[Observation]:
        backend = self._backend()
        if backend == "journalctl":
            new_observations = self._read_journalctl()
        elif backend == "dmesg":
            new_observations = self._read_dmesg()
        else:
            raise RuntimeError("no kernel log backend available")
        return self._merge(new_observations)
