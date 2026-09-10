# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Probe base class and shared subprocess helpers."""

from __future__ import annotations

import abc
import collections
import functools
import shutil
import subprocess
import threading
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


#: Hard cap on how much of a command's stdout we hold in memory *while it runs*.
#: `journalctl` / `dmesg` on a long or noisy session can emit tens of MB; past
#: this the oldest lines are dropped (the newest matter most) and the result is
#: flagged ``.truncated``.
MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_STDERR_BYTES = 64 * 1024


class Captured(str):
    """A command's stdout. ``.truncated`` is True if it exceeded the cap."""

    truncated: bool = False


def _flag(text: str, *, truncated: bool) -> Captured:
    out = Captured(text)
    out.truncated = truncated
    return out


class _BoundedReader(threading.Thread):
    """Drain a pipe into <= ``cap`` bytes without ever holding more than that."""

    def __init__(self, stream, cap: int, *, front_drop: bool) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._cap = cap
        self._front_drop = front_drop
        self.data = b""
        self.truncated = False

    def run(self) -> None:
        chunks: collections.deque[bytes] = collections.deque()
        size = 0
        try:
            for chunk in iter(lambda: self._stream.read(65536), b""):
                if self._front_drop:
                    chunks.append(chunk)
                    size += len(chunk)
                    while size > self._cap and len(chunks) > 1:
                        size -= len(chunks.popleft())
                        self.truncated = True
                elif size < self._cap:
                    take = chunk[: self._cap - size]
                    chunks.append(take)
                    size += len(take)
                    self.truncated = self.truncated or len(take) < len(chunk)
                else:
                    self.truncated = True
        except (OSError, ValueError):  # pragma: no cover - pipe closed under us
            pass
        self.data = b"".join(chunks)


def run_command(args: list[str], *, timeout: float = 15.0) -> tuple[int, Captured, str]:
    """Run ``args`` and return ``(returncode, stdout, stderr)``.

    Never raises for ordinary failures; returns ``(-1, "", reason)`` instead.
    stdout is streamed into a bounded buffer *while the process runs* (oldest
    lines dropped past :data:`MAX_COMMAND_OUTPUT_BYTES`); check
    ``stdout.truncated``.
    """

    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        return -1, _flag("", truncated=False), f"command not found: {args[0]}"
    except OSError as exc:  # pragma: no cover - defensive
        return -1, _flag("", truncated=False), f"failed to run {' '.join(args)}: {exc}"

    out_reader = _BoundedReader(proc.stdout, MAX_COMMAND_OUTPUT_BYTES, front_drop=True)
    err_reader = _BoundedReader(proc.stderr, _MAX_STDERR_BYTES, front_drop=False)
    out_reader.start()
    err_reader.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    out_reader.join(timeout=5.0)
    err_reader.join(timeout=5.0)

    out = _truncate_marker(out_reader.data, out_reader.truncated)
    err = err_reader.data.decode("utf-8", "replace")
    if timed_out:
        err = (err + f"\ncommand timed out after {timeout}s: {' '.join(args)}").strip()
        return -1, out, err
    return proc.returncode, out, err


def _truncate_marker(data: bytes, truncated: bool) -> Captured:
    text = data.decode("utf-8", "replace")
    if not truncated:
        return _flag(text, truncated=False)
    # drop a partial first line so parsers see whole records only
    _, _, tail = text.partition("\n")
    return _flag(
        f"[... earlier output dropped: kept the last {len(tail)} bytes ...]\n" + tail,
        truncated=True,
    )
