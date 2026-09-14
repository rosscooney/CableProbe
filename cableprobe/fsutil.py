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

Pathname-based checks like the above have a residual gap: they inspect the
*name* at check time, but a later write still resolves that same name again -
an attacker who can replace the directory (or a component above it) between
the check and the write races past the check entirely. The functions below
close that window for privileged callers:

* :func:`verify_directory_chain` walks *every* ancestor of a path (not just
  the leaf), so a symlink several levels up cannot pass a leaf-only check.
* :func:`open_verified_dir` performs that check and then opens the directory
  itself with ``O_NOFOLLOW`` for a genuinely fixed vantage point, returning a
  file descriptor. Every subsequent operation anchored to that descriptor
  (:func:`atomic_write_at`, :func:`read_text_nofollow_at`) uses the ``*at()``
  family of syscalls (``dir_fd=``) and therefore always targets the directory
  the fd was opened for - not whatever a later, possibly-replaced pathname
  happens to resolve to.
"""

from __future__ import annotations

import os
import secrets
import stat
import tempfile
from pathlib import Path

#: Owner-only. Reports carry host details, MAC addresses and process cmdlines.
PRIVATE_FILE_MODE = 0o600

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


class UnsafeDirectoryError(OSError):
    """A directory (or one of its ancestors) failed a privileged-write trust
    check: a symlink in the chain, wrong ownership, or group/other-writable."""


class UnsafePathError(OSError):
    """A file (as opposed to a directory) failed the same kind of trust check."""


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


def atomic_write_at(
    dir_fd: int, name: str, text: str, *, mode: int = PRIVATE_FILE_MODE
) -> None:
    """Like :func:`atomic_write`, but anchored to an already-open, verified
    directory descriptor (see :func:`open_verified_dir`) instead of a
    pathname.

    Every operation here - the temp file's creation, and the final rename -
    uses ``dir_fd=``, so all of them target the directory the descriptor was
    opened for, never whatever a pathname happens to resolve to at the moment
    of the call. A directory swapped out *after* the descriptor was opened
    (the TOCTOU window a pathname-only check like :func:`unsafe_output_dir_reasons`
    cannot close on its own) therefore cannot redirect this write.
    ``name`` must be a bare filename (no path separators).
    """

    if not name or "/" in name or name in (".", ".."):
        raise ValueError(f"unsafe file name: {name!r}")
    tmp_name = f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    fd = os.open(
        tmp_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
        mode,
        dir_fd=dir_fd,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError:  # pragma: no cover
            pass
        raise


def open_verified_dir(
    directory: Path | str,
    *,
    invoking_uid: int | None = None,
    create: bool = False,
    mode: int = 0o700,
) -> int:
    """Validate the full ancestor chain of ``directory`` (see
    :func:`verify_directory_chain`), then open it with ``O_NOFOLLOW`` and
    return the resulting file descriptor.

    Pass the returned fd as ``dir_fd`` to :func:`atomic_write_at` /
    :func:`read_text_nofollow_at` (and close it when done - a context manager
    is not provided because callers typically hold it across several
    operations). Once open, the fd keeps referring to the directory that was
    actually verified regardless of what happens to the pathname afterwards -
    the residual gap a pathname-only check cannot close.

    Raises :class:`UnsafeDirectoryError` if any *existing* ancestor fails the
    trust check. With ``create=True``, a missing ``directory`` (and any
    missing ancestors) is created - but only after the chain above it has
    already been confirmed safe; a symlink swapped in for the leaf between
    that check and this function's own final open is still refused, because
    the open itself uses ``O_NOFOLLOW``.
    """

    directory = Path(directory)
    reasons = verify_directory_chain(directory, invoking_uid=invoking_uid)
    if reasons:
        raise UnsafeDirectoryError(
            f"refusing to trust {directory} for a privileged read/write: "
            + "; ".join(reasons)
        )
    if create:
        directory.mkdir(parents=True, exist_ok=True, mode=mode)
    return os.open(directory, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)


def _read_regular_fd(
    fd: int, *, name: str, encoding: str, max_bytes: int | None
) -> str:
    """Shared body of :func:`read_text_nofollow` / :func:`read_text_nofollow_at`:
    verify the already-opened ``fd`` is a regular file, bound its size, and
    read it. Does not close ``fd`` - the caller owns that."""

    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise OSError(f"{name} is not a regular file")
    if max_bytes is not None and st.st_size > max_bytes:
        raise ValueError(
            f"{name} is {st.st_size} bytes (> {max_bytes}); refusing to load"
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
    return b"".join(chunks).decode(encoding)


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
        return _read_regular_fd(
            fd, name=Path(path).name, encoding=encoding, max_bytes=max_bytes
        )
    finally:
        os.close(fd)


def read_text_nofollow_at(
    dir_fd: int,
    name: str,
    *,
    encoding: str = "utf-8",
    max_bytes: int | None = None,
) -> str:
    """Like :func:`read_text_nofollow`, but anchored to an already-open
    directory descriptor (see :func:`open_verified_dir`) instead of a
    pathname - a directory swap after the fd was opened cannot redirect this
    read. ``name`` must be a bare filename (no path separators)."""

    if not name or "/" in name or name in (".", ".."):
        raise ValueError(f"unsafe file name: {name!r}")
    fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK, dir_fd=dir_fd)
    try:
        return _read_regular_fd(fd, name=name, encoding=encoding, max_bytes=max_bytes)
    finally:
        os.close(fd)


def probe_dir_writable(directory: Path | str) -> None:
    """Raise ``OSError`` unless a fresh file can be created in ``directory``.

    Uses a uniquely named, exclusively-created temp file (no predictable name,
    nothing to symlink onto) and removes it again.
    """

    fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".cableprobe-writetest.")
    os.close(fd)
    os.unlink(tmp)


def trusted_owners(invoking_uid: int | None) -> set[int]:
    """The uids allowed to own a directory/file this process will trust.

    Always root and the process's own effective uid (whoever is actually
    running right now legitimately owns their own files), plus the uid behind
    ``sudo`` (``$SUDO_UID``) if any - the same policy ``_guard_output_dir``
    has always used for the output directory when running as root, applied
    consistently everywhere trust is checked, and extended to make sense for
    a non-privileged run too (root is a no-op there: the effective uid already
    covers "my own files").
    """

    owners = {0, os.geteuid()} if hasattr(os, "geteuid") else {0}
    if invoking_uid is not None:
        owners.add(invoking_uid)
    return owners


def _entry_reasons(
    label: str, lst: os.stat_result, *, invoking_uid: int | None, expect_dir: bool
) -> list[str]:
    """Reasons one already-lstat'd path entry is untrustworthy."""

    if stat.S_ISLNK(lst.st_mode):
        # a symlink's own permission bits are not meaningful - the kernel
        # ignores them, and different platforms report different values for
        # them (0o777 is conventional on Linux, but not universal) - being a
        # symlink at all is reason enough, so do not also check owner/mode.
        return [f"{label} is a symlink"]
    reasons: list[str] = []
    if expect_dir and not stat.S_ISDIR(lst.st_mode):
        reasons.append(f"{label} is not a directory")
    elif not expect_dir and not stat.S_ISREG(lst.st_mode):
        reasons.append(f"{label} is not a regular file")
    if lst.st_uid not in trusted_owners(invoking_uid):
        reasons.append(f"{label} is owned by uid {lst.st_uid}, not root or the invoking user")
    if lst.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        reasons.append(f"{label} is writable by other users")
    return reasons


def verify_directory_chain(
    directory: Path | str, *, invoking_uid: int | None = None
) -> list[str]:
    """Reasons ANY existing component of ``directory``'s path - not just the
    leaf - is unsafe to trust for a privileged read or write.

    Walks from the filesystem root using ``lstat`` (never resolving
    symlinks), so a symlinked ancestor several levels up is caught even
    though the leaf itself looks fine. A component that does not exist yet is
    not a problem here - the caller may still need to create it - and once a
    component is missing every deeper one necessarily is too, so the walk
    naturally stops flagging anything past that point.
    """

    d = Path(directory)
    if not d.is_absolute():
        d = Path.cwd() / d
    reasons: list[str] = []
    current = Path(d.anchor)
    for part in d.parts[len(Path(d.anchor).parts) :]:
        current = current / part
        try:
            lst = current.lstat()
        except OSError:
            break  # this and every deeper component are absent - fine
        reasons.extend(
            _entry_reasons(str(current), lst, invoking_uid=invoking_uid, expect_dir=True)
        )
    return reasons


def unsafe_file_reasons(path: Path | str, *, invoking_uid: int | None = None) -> list[str]:
    """Reasons ``path`` itself (not its directory) is unsafe to trust: a
    symlink, a non-regular file, wrong ownership, or group/other-writable.
    An absent path is not a problem here - that is the caller's to decide."""

    p = Path(path)
    try:
        lst = p.lstat()
    except OSError:
        return []
    return _entry_reasons(str(p), lst, invoking_uid=invoking_uid, expect_dir=False)


def unsafe_output_dir_reasons(
    directory: Path | str, *, invoking_uid: int | None
) -> list[str]:
    """Reasons ``directory`` - or any ancestor of it - is risky to write into
    with elevated privileges.

    ``invoking_uid`` is the uid behind ``sudo`` (``$SUDO_UID``), which is also
    allowed to own the directory. An empty list means "looks fine" (or the
    directory does not exist yet, which is not this function's problem).
    """

    return verify_directory_chain(directory, invoking_uid=invoking_uid)
