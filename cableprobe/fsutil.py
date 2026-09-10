# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Symlink-safe filesystem helpers for privileged writes.

CableProbe frequently runs as root and writes into a session output directory
whose path is predictable (``<output_dir>/.cableprobe-index.json``, the
allowlist, the report files). If that directory is writable by another user, a
symlink planted at a known name would let a root-owned write land on an
arbitrary file - truncating it, or exposing report contents.

* :func:`atomic_write` creates a fresh file and renames it into place, so the
  write can never follow a symlink at the destination.
* :func:`read_text_nofollow` refuses to read through a symlink.
* :func:`probe_dir_writable` / :func:`unsafe_output_dir_reasons` let the CLI
  check the directory before it trusts it.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

#: Owner-only. Reports carry host details, MAC addresses and process cmdlines.
PRIVATE_FILE_MODE = 0o600

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def atomic_write(path: Path | str, text: str, *, mode: int = PRIVATE_FILE_MODE) -> Path:
    """Write ``text`` to ``path`` atomically, without ever following a symlink.

    A fresh temp file is created in the same directory (``mkstemp`` uses
    ``O_CREAT | O_EXCL`` at mode 0600, so it cannot land on an existing file or
    symlink), written, ``fchmod``-ed to ``mode``, then ``os.replace``-d onto
    ``path``. ``rename(2)`` swaps whatever is at the destination name - a
    symlink included - without following it, and readers never see a
    half-written file.
    """

    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, mode)
            except OSError:  # pragma: no cover - unusual filesystems
                pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:  # pragma: no cover
            pass
        raise
    return path


def read_text_nofollow(
    path: Path | str, *, encoding: str = "utf-8", max_bytes: int | None = None
) -> str:
    """Read a regular text file safely.

    ``O_NOFOLLOW`` (no symlink at the final component) and ``O_NONBLOCK`` plus
    an ``fstat`` regular-file check mean a symlink, a FIFO or a device planted
    at a predictable path cannot make this block on ``open`` or ``read``. Reads
    at most ``max_bytes`` (+1, to detect overflow). Raises ``OSError`` for a
    non-regular / missing file, ``ValueError`` past ``max_bytes``.
    """

    fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"{Path(path).name} is not a regular file")
        if max_bytes is not None and st.st_size > max_bytes:
            raise ValueError(
                f"{Path(path).name} is {st.st_size} bytes (> {max_bytes}); "
                "refusing to load"
            )
        cap = st.st_size if max_bytes is None else min(st.st_size, max_bytes + 1)
        chunks: list[bytes] = []
        got = 0
        while got < cap:
            chunk = os.read(fd, min(1024 * 1024, cap - got))
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks).decode(encoding)


def probe_dir_writable(directory: Path | str) -> None:
    """Raise ``OSError`` unless a fresh file can be created in ``directory``.

    Uses a uniquely named, exclusively-created temp file (no predictable name,
    nothing to symlink onto) and removes it again.
    """

    fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".cableprobe-writetest.")
    os.close(fd)
    os.unlink(tmp)


def unsafe_output_dir_reasons(
    directory: Path | str, *, invoking_uid: int | None
) -> list[str]:
    """Reasons ``directory`` is risky to write into with elevated privileges.

    ``invoking_uid`` is the uid behind ``sudo`` (``$SUDO_UID``), which is also
    allowed to own the directory. An empty list means "looks fine" (or the
    directory does not exist yet, which is not this function's problem).
    """

    d = Path(directory)
    try:
        lst = d.lstat()
    except OSError:
        return []
    if stat.S_ISLNK(lst.st_mode):
        return [f"{d} is a symlink"]
    reasons: list[str] = []
    allowed = {0} | ({invoking_uid} if invoking_uid is not None else set())
    if lst.st_uid not in allowed:
        reasons.append(
            f"{d} is owned by uid {lst.st_uid}, not root or the invoking user"
        )
    if lst.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        reasons.append(f"{d} is writable by other users")
    return reasons
