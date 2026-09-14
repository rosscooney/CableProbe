# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from cableprobe.fsutil import (
    UnsafeDirectoryError,
    atomic_write,
    atomic_write_at,
    open_verified_dir,
    probe_dir_writable,
    read_text_nofollow,
    read_text_nofollow_at,
    unsafe_file_reasons,
    unsafe_output_dir_reasons,
    verify_directory_chain,
)


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_atomic_write_creates_private_file(tmp_path):
    p = atomic_write(tmp_path / "r.json", "hello")
    assert p.read_text() == "hello"
    assert _mode(p) == 0o600
    # no leftover temp files
    assert [q.name for q in tmp_path.iterdir()] == ["r.json"]


def test_atomic_write_custom_mode(tmp_path):
    p = atomic_write(tmp_path / "allow.yaml", "x", mode=0o644)
    assert _mode(p) == 0o644


def test_atomic_write_replaces_a_preexisting_loose_file(tmp_path):
    victim = tmp_path / "r.json"
    victim.write_text("{}")
    os.chmod(victim, 0o666)
    atomic_write(victim, "new")
    assert victim.read_text() == "new" and _mode(victim) == 0o600


def test_atomic_write_does_not_follow_a_symlinked_target(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("SECRET")
    link = tmp_path / ".cableprobe-index.json"
    link.symlink_to(secret)

    atomic_write(link, '{"ok": true}')

    assert secret.read_text() == "SECRET"  # the real file is untouched
    assert not link.is_symlink()  # the symlink was replaced by a regular file
    assert link.read_text() == '{"ok": true}'


def test_atomic_write_cleans_up_on_failure(tmp_path):
    with pytest.raises(TypeError):
        atomic_write(tmp_path / "r.json", 123)  # type: ignore[arg-type]
    assert list(tmp_path.iterdir()) == []  # temp file removed, target not created


def test_read_text_nofollow_rejects_symlink(tmp_path):
    real = tmp_path / "real"
    real.write_text("data")
    link = tmp_path / "link"
    link.symlink_to(real)

    assert read_text_nofollow(real) == "data"
    with pytest.raises(OSError):
        read_text_nofollow(link)


def test_read_text_nofollow_size_cap(tmp_path):
    f = tmp_path / "big"
    f.write_text("x" * 100)
    assert read_text_nofollow(f, max_bytes=1000) == "x" * 100
    with pytest.raises(ValueError, match="refusing to load"):
        read_text_nofollow(f, max_bytes=10)


def test_read_text_nofollow_rejects_a_fifo(tmp_path):
    fifo = tmp_path / "index.json"
    os.mkfifo(fifo)  # open()/read() on this would block a naive reader
    with pytest.raises(OSError):
        read_text_nofollow(fifo)


def test_probe_dir_writable(tmp_path):
    probe_dir_writable(tmp_path)  # does not raise
    assert list(tmp_path.iterdir()) == []  # cleaned up

    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    ro = tmp_path / "ro"
    ro.mkdir()
    os.chmod(ro, 0o500)
    try:
        with pytest.raises(OSError):
            probe_dir_writable(ro)
    finally:
        os.chmod(ro, 0o700)


def test_unsafe_output_dir_reasons(tmp_path):
    uid = os.getuid()
    assert unsafe_output_dir_reasons(tmp_path, invoking_uid=uid) == []

    os.chmod(tmp_path, 0o777)
    try:
        reasons = unsafe_output_dir_reasons(tmp_path, invoking_uid=uid)
        assert any("writable by other users" in r for r in reasons)
    finally:
        os.chmod(tmp_path, 0o755)

    (tmp_path / "real").mkdir()
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "real")
    assert unsafe_output_dir_reasons(link, invoking_uid=uid) == [f"{link} is a symlink"]

    # missing dir is not this function's problem
    assert unsafe_output_dir_reasons(tmp_path / "nope", invoking_uid=uid) == []


def test_verify_directory_chain_catches_a_symlinked_ancestor(tmp_path):
    uid = os.getuid()
    real_parent = tmp_path / "real_parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked_parent"
    linked_parent.symlink_to(real_parent)
    leaf = linked_parent / "reports"  # does not exist yet - the ancestor above it does

    reasons = verify_directory_chain(leaf, invoking_uid=uid)
    assert any(str(linked_parent) in r and "symlink" in r for r in reasons)

    # a normal chain (nothing to complain about) reports nothing
    assert verify_directory_chain(real_parent / "reports", invoking_uid=uid) == []


def test_verify_directory_chain_flags_a_foreign_owned_ancestor(tmp_path, monkeypatch):
    class _FakeStat:
        def __init__(self, uid, mode):
            self.st_uid = uid
            self.st_mode = mode

    import stat as stat_mod

    real_lstat = Path.lstat

    def fake_lstat(self):
        if self.name == "foreign":
            return _FakeStat(65534, stat_mod.S_IFDIR | 0o755)
        return real_lstat(self)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    foreign = tmp_path / "foreign"
    reasons = verify_directory_chain(foreign / "reports", invoking_uid=os.getuid())
    assert any("owned by uid 65534" in r for r in reasons)


def test_unsafe_file_reasons(tmp_path):
    uid = os.getuid()
    f = tmp_path / "allowlist.yaml"
    f.write_text("allow: []")
    assert unsafe_file_reasons(f, invoking_uid=uid) == []

    os.chmod(f, 0o666)
    try:
        reasons = unsafe_file_reasons(f, invoking_uid=uid)
        assert any("writable by other users" in r for r in reasons)
    finally:
        os.chmod(f, 0o644)

    link = tmp_path / "link.yaml"
    link.symlink_to(f)
    assert unsafe_file_reasons(link, invoking_uid=uid) == [f"{link} is a symlink"]

    fifo = tmp_path / "fifo.yaml"
    os.mkfifo(fifo)
    reasons = unsafe_file_reasons(fifo, invoking_uid=uid)
    assert any("not a regular file" in r for r in reasons)

    # missing file is not this function's problem
    assert unsafe_file_reasons(tmp_path / "nope.yaml", invoking_uid=uid) == []


def test_open_verified_dir_returns_a_usable_fd(tmp_path):
    fd = open_verified_dir(tmp_path, invoking_uid=os.getuid())
    try:
        assert isinstance(fd, int) and fd >= 0
        atomic_write_at(fd, "x.txt", "hello")
        assert (tmp_path / "x.txt").read_text() == "hello"
        assert read_text_nofollow_at(fd, "x.txt") == "hello"
    finally:
        os.close(fd)


def test_open_verified_dir_creates_when_asked(tmp_path):
    target = tmp_path / "a" / "b" / "sessions"
    fd = open_verified_dir(target, invoking_uid=os.getuid(), create=True)
    try:
        assert target.is_dir()
    finally:
        os.close(fd)


def test_open_verified_dir_refuses_a_symlinked_ancestor(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real)
    with pytest.raises(UnsafeDirectoryError):
        open_verified_dir(linked / "sessions", invoking_uid=os.getuid(), create=True)
    # nothing was created through the symlink
    assert not (real / "sessions").exists()


def test_open_verified_dir_refuses_when_leaf_replaced_with_symlink_after_check(
    tmp_path, monkeypatch
):
    """Simulates the exact race the fd-anchoring is meant to close: the
    directory looks fine when verify_directory_chain runs, but by the time
    the actual open() happens (here: forced via monkeypatch) it has been
    swapped for a symlink. The O_NOFOLLOW open must still refuse it."""

    from cableprobe import fsutil as fsutil_mod

    target = tmp_path / "sessions"
    target.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    real_verify = fsutil_mod.verify_directory_chain

    def swap_after_check(directory, **kwargs):
        reasons = real_verify(directory, **kwargs)
        target.rmdir()
        target.symlink_to(elsewhere)
        return reasons

    monkeypatch.setattr(fsutil_mod, "verify_directory_chain", swap_after_check)
    with pytest.raises(OSError):
        open_verified_dir(target, invoking_uid=os.getuid())


def test_atomic_write_at_rejects_unsafe_names(tmp_path):
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError):
            atomic_write_at(fd, "../escape", "x")
        with pytest.raises(ValueError):
            atomic_write_at(fd, "nested/name", "x")
    finally:
        os.close(fd)


def test_atomic_write_at_cleans_up_temp_file_on_failure(tmp_path):
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        with pytest.raises(TypeError):
            atomic_write_at(fd, "r.json", 123)  # type: ignore[arg-type]
    finally:
        os.close(fd)
    assert list(tmp_path.iterdir()) == []  # no leftover temp file, no target
