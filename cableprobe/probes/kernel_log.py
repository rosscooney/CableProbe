# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Kernel ring-buffer / journal capture, filtered to USB-relevant lines.

Captures kernel messages emitted since the session started and keeps the ones
matching a keyword list (USB enumeration, HID, CDC/RNDIS ethernet gadgets, hub
activity, descriptor-read errors, etc.).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_KERNEL_MESSAGE, Observation
from cableprobe.probes.base import Probe, ProbeAvailability, have_tool, run_command

log = get_logger("probe.kernel")

DEFAULT_KEYWORDS = [
    "usb",
    "hub",
    "hid",
    "input",
    "cdc_ether",
    "cdc_ncm",
    "cdc_acm",
    "rndis",
    "usbnet",
    "ax88",
    "r8152",
    "new full-speed",
    "new high-speed",
    "new low-speed",
    "new SuperSpeed",
    "device descriptor read",
    "unable to enumerate",
    "over-current",
    "not accepting address",
    "device not accepting",
    "ep0 in",
    "-71",
    "-110",
]

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


class KernelLogProbe(Probe):
    name = "kernel_log"
    description = "USB-relevant kernel log / journal lines emitted during the session"
    # Cumulative since session start and relatively expensive; capturing it on
    # every in-phase tick just re-reads and re-parses the same growing log.
    samples_periodically = False

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
        return DEFAULT_KEYWORDS + list(self.config.probes.kernel_log_keywords)

    def snapshot(self) -> list[Observation]:
        backend = self._backend()
        since = datetime.fromtimestamp(self.session_start, tz=timezone.utc)

        if backend == "journalctl":
            code, out, err = run_command(
                [
                    "journalctl",
                    "-k",
                    "--no-pager",
                    "-o",
                    "short-iso",
                    "--since",
                    since.astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                ],
                timeout=20.0,
            )
            if code != 0:
                raise RuntimeError(err.strip() or "journalctl failed")
            return filter_kernel_lines(out.splitlines(), self._keywords())

        if backend == "dmesg":
            code, out, err = run_command(["dmesg", "--ctime"], timeout=20.0)
            if code != 0:
                code, out, err = run_command(["dmesg"], timeout=20.0)
            if code != 0:
                raise RuntimeError(err.strip() or "dmesg failed")
            return filter_kernel_lines(out.splitlines(), self._keywords())

        raise RuntimeError("no kernel log backend available")
