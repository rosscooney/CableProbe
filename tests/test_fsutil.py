# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import stat

import pytest

from cableprobe.fsutil import (
    atomic_write,
    probe_dir_writable,
    read_text_nofollow,
    unsafe_output_dir_reasons,
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
