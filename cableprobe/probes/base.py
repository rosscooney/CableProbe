# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Probe base class and shared subprocess helpers."""

from __future__ import annotations

import abc
import functools
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cableprobe.config import Config
from cableprobe.logging_config import get_logger
from cableprobe.models import Observation, ProbeEvent

log = get_logger("probe")


@functools.lru_cache(maxsize=1)
def udev_context() -> Any:
    """Return a process-wide cached ``pyudev.Context``.

    Creating a Context per snapshot (every sampling tick) is wasteful; enumeration
    on a shared Context is safe. Raises if pyudev is unavailable - callers guard.
    """

    import pyudev

    return pyudev.Context()


@dataclass(frozen=True)
class ProbeAvailability:
    ok: bool
    detail: str = ""


class Probe(abc.ABC):
    """Base class for all probes."""

    #: Stable short name, also the key used in configuration.
    name: str = "probe"
    #: One-line human description.
    description: str = ""

    def __init__(self, config: Config, session_start: float) -> None:
        self.config = config
        self.session_start = session_start

    # -- lifecycle --------------------------------------------------------

    def availability(self) -> ProbeAvailability:
        """Return whether this probe can run. Override for real checks."""

        return ProbeAvailability(ok=True)

    async def start(self) -> None:
        """Begin any background monitoring. Default: no-op."""

    async def stop(self) -> None:
        """Tear down background monitoring. Default: no-op."""

    # -- data -----------------------------------------------------------

    @abc.abstractmethod
    def snapshot(self) -> list[Observation]:
        """Return the current point-in-time observations.

        Called from a worker thread (via ``asyncio.to_thread``), so it may block
        on subprocesses and filesystem reads.
        """

    def drain_events(self) -> list[ProbeEvent]:
        """Return and clear any asynchronous events seen since the last call."""

        return []

    def dropped_events(self) -> int:
        """Return and reset the count of events this probe had to discard
        (its own buffer overflowed). Default: nothing is ever dropped."""

        return 0


# --------------------------------------------------------------------------
# subprocess helpers
# --------------------------------------------------------------------------


def have_tool(name: str) -> bool:
    return shutil.which(name) is not None


def read_sysfs(path: Path | str, default: str | None = None) -> str | None:
    """Read a sysfs / procfs text attribute.

    Returns the file's stripped contents, or ``default`` if the file is missing,
    unreadable, or empty after stripping.
    """

    try:
        value = Path(path).read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return default
    return value or default


def sysfs_device_is_usb(sys_dir: Path | str) -> bool:
    """True if the ``device`` symlink under a ``/sys/class/<x>/<name>`` dir
    resolves to a path that traverses the USB bus."""

    link = Path(sys_dir) / "device"
    try:
        return "/usb" in str(link.resolve()).lower()
    except OSError:
        return False


def sysfs_driver(sys_dir: Path | str) -> str | None:
    """Return the bound kernel driver name for a ``/sys/class/<x>/<name>`` dir."""

    link = Path(sys_dir) / "device" / "driver"
    try:
        return link.resolve().name
    except OSError:
        return None


def run_command(args: list[str], *, timeout: float = 15.0) -> tuple[int, str, str]:
    """Run ``args`` and return ``(returncode, stdout, stderr)``.

    Never raises for ordinary failures; returns ``(-1, "", reason)`` instead.
    """

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return -1, "", f"command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"command timed out after {timeout}s: {' '.join(args)}"
    except OSError as exc:  # pragma: no cover - defensive
        return -1, "", f"failed to run {' '.join(args)}: {exc}"
    return proc.returncode, proc.stdout, proc.stderr
