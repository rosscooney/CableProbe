# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Probe base class and shared subprocess helpers."""

from __future__ import annotations

import abc
import collections
import functools
import os
import shutil
import signal
import subprocess
import threading
import time
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

#: After the process has exited (or been killed) the reader threads get this
#: long to drain what is left in the pipe. A descendant that inherited stdout
#: and outlived its parent - or that escaped the killed process group - can hold
#: the write end open forever; past this grace the capture is reported
#: incomplete rather than blocking the snapshot.
_DRAIN_GRACE_SECONDS = 5.0


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
        self._lock = threading.Lock()
        self._chunks: collections.deque[bytes] = collections.deque()
        self._size = 0
        self.truncated = False

    def run(self) -> None:
        # read1(): hand back each syscall's worth as soon as it arrives, so
        # buffered data is retrievable even if the pipe never reaches EOF
        # (a descendant holding the write end open). Plain read() would sit on
        # up to 64 KiB until EOF.
        reader = getattr(self._stream, "read1", None) or self._stream.read
        try:
            for chunk in iter(lambda: reader(65536), b""):
                with self._lock:
                    if self._front_drop:
                        self._chunks.append(chunk)
                        self._size += len(chunk)
                        while self._size > self._cap and len(self._chunks) > 1:
                            self._size -= len(self._chunks.popleft())
                            self.truncated = True
                    elif self._size < self._cap:
                        take = chunk[: self._cap - self._size]
                        self._chunks.append(take)
                        self._size += len(take)
                        self.truncated = self.truncated or len(take) < len(chunk)
                    else:
                        self.truncated = True
        except (OSError, ValueError):  # pragma: no cover - pipe closed under us
            pass

    @property
    def data(self) -> bytes:
        """What has been drained so far - safe to read while the thread runs,
        so a reader stuck on a descendant-held pipe still yields partial output.
        """

        with self._lock:
            return b"".join(self._chunks)


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Kill the process *and everything it spawned*.

    ``start_new_session=True`` makes ``proc`` the leader of its own process
    group, so one ``killpg`` reaches descendants that would otherwise keep the
    stdout pipe open after the parent is gone.
    """

    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):  # pragma: no cover
        pass
    try:
        proc.kill()
    except OSError:  # pragma: no cover - already dead
        pass


def run_command(args: list[str], *, timeout: float = 15.0) -> tuple[int, Captured, str]:
    """Run ``args`` and return ``(returncode, stdout, stderr)``.

    Never raises for ordinary failures; returns ``(-1, "", reason)`` instead.
    stdout is streamed into a bounded buffer *while the process runs* (oldest
    lines dropped past :data:`MAX_COMMAND_OUTPUT_BYTES`); check
    ``stdout.truncated``.

    One overall deadline covers both process execution and pipe draining. If a
    descendant inherits stdout and outlives the parent (or escapes the killed
    process group), the capture is returned as ``-1`` with ``.truncated`` set
    and whatever was buffered - never a clean ``0`` with missing output.
    """

    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
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
        timed_out = True
        _kill_process_tree(proc)
        try:
            proc.wait(timeout=_DRAIN_GRACE_SECONDS)
        except subprocess.TimeoutExpired:  # pragma: no cover - unkillable zombie
            pass

    # Bounded drain: once the process is gone the pipe normally EOFs at once. A
    # reader still alive past the grace is blocked on a descendant that kept the
    # write end open - take what it has and flag the capture incomplete. The
    # readers are daemon threads, so a stuck one never blocks interpreter exit.
    drain_until = time.monotonic() + _DRAIN_GRACE_SECONDS
    for reader in (out_reader, err_reader):
        reader.join(timeout=max(0.0, drain_until - time.monotonic()))
    incomplete = out_reader.is_alive() or err_reader.is_alive()
    if incomplete and not timed_out:
        # the process exited cleanly but left a descendant holding the pipe -
        # reap the group so it does not linger for the rest of the session
        _kill_process_tree(proc)

    out = _truncate_marker(out_reader.data, out_reader.truncated)
    err = err_reader.data.decode("utf-8", "replace")
    if incomplete:
        # the buffered prefix is intact from the start here (unlike front-drop
        # truncation), so keep it and just note the tail is missing
        out = _flag(out.rstrip("\n") + "\n[... output capture incomplete ...]\n", truncated=True)
        err = (
            err
            + f"\noutput capture incomplete: a child kept stdout open past "
            f"{timeout}s: {' '.join(args)}"
        ).strip()
    if timed_out:
        err = (err + f"\ncommand timed out after {timeout}s: {' '.join(args)}").strip()
        return -1, out, err
    if incomplete:
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
