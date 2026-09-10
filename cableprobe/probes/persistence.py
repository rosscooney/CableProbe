# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Watch the host's persistence surface.

A cable payload that wants to survive a reboot has to write somewhere the system
reads at boot, on a device event, or at login. This probe fingerprints those
places - udev rules, systemd units, cron, ``/etc/hosts``, ``authorized_keys``,
``rc.local``, ``ld.so.preload`` - and any change during a session is a strong
signal.

Content-hashed, so a touch that doesn't change the bytes is ignored.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_PERSISTENCE_ITEM, Observation
from cableprobe.probes.base import Probe, ProbeAvailability

log = get_logger("probe.persistence")

#: (label, glob or file). Directories are globbed; files are hashed directly.
_TARGETS: list[tuple[str, str]] = [
    ("udev-rule", "/etc/udev/rules.d/*.rules"),
    ("systemd-unit", "/etc/systemd/system/*.service"),
    ("systemd-timer", "/etc/systemd/system/*.timer"),
    ("cron.d", "/etc/cron.d/*"),
    ("cron-hourly", "/etc/cron.hourly/*"),
    ("crontab", "/etc/crontab"),
    ("user-crontab", "/var/spool/cron/crontabs/*"),
    ("hosts", "/etc/hosts"),
    ("rc.local", "/etc/rc.local"),
    ("ld.so.preload", "/etc/ld.so.preload"),
    ("profile.d", "/etc/profile.d/*.sh"),
]

_HOME_ROOTS = ("/root", "/home")

#: Cap on how much of a persistence file we hash. These files are tiny; a huge
#: one is a mistake or an attempt to make the scan expensive.
_MAX_HASH_BYTES = 8 * 1024 * 1024

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _fingerprint(path: Path) -> dict:
    """Hash ``path`` safely.

    Opens with ``O_NOFOLLOW | O_NONBLOCK`` (a symlink or a FIFO can't make us
    block or follow it elsewhere), rejects anything that is not a regular file,
    and hashes at most :data:`_MAX_HASH_BYTES`. A local user who plants a FIFO
    or a symlink to ``/dev/zero`` at a discovered ``authorized_keys`` path can
    no longer hang or OOM the session.
    """

    info: dict = {
        "sha256": None,
        "size": None,
        "present": False,
        "regular_file": None,
        "hash_truncated": False,
    }
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
    except OSError:
        return info
    try:
        st = os.fstat(fd)
        info["present"] = True
        info["size"] = st.st_size
        if not stat.S_ISREG(st.st_mode):
            info["regular_file"] = False
            return info
        info["regular_file"] = True
        digest = hashlib.sha256()
        remaining = _MAX_HASH_BYTES
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        else:
            info["hash_truncated"] = bool(os.read(fd, 1))
        info["sha256"] = digest.hexdigest()
    except OSError:
        pass
    finally:
        os.close(fd)
    return info


def _authorized_keys_paths(home_roots: tuple[str, ...] = _HOME_ROOTS) -> list[Path]:
    out: list[Path] = []
    for root in home_roots:
        base = Path(root)
        try:
            if not base.is_dir():
                continue
            homes = (
                [base] if base.name == "root" else [d for d in base.iterdir() if d.is_dir()]
            )
        except OSError:
            continue
        for home in homes:
            for name in ("authorized_keys", "authorized_keys2"):
                p = home / ".ssh" / name
                try:
                    if p.exists():
                        out.append(p)
                except OSError:
                    continue
    return out


def scan_persistence(
    targets: list[tuple[str, str]] | None = None,
    home_roots: tuple[str, ...] | None = _HOME_ROOTS,
) -> list[Observation]:
    observations: list[Observation] = []
    seen: set[str] = set()

    def _emit(label: str, path: Path) -> None:
        key = str(path)
        if key in seen:
            return
        seen.add(key)
        fp = _fingerprint(path)
        observations.append(
            Observation(
                kind=KIND_PERSISTENCE_ITEM,
                identity=f"persist:{key}",
                label=f"{label}: {key}",
                attributes={
                    "path": key,
                    "category": label,
                    "sha256": fp["sha256"],
                    "size": fp["size"],
                    "present": fp["present"],
                    "regular_file": fp["regular_file"],
                    "hash_truncated": fp["hash_truncated"],
                },
            )
        )

    for label, pattern in targets or _TARGETS:
        p = Path(pattern)
        if any(ch in pattern for ch in "*?["):
            for match in sorted(p.parent.glob(p.name)):
                if match.is_file():
                    _emit(label, match)
        elif p.is_file():
            _emit(label, p)

    for keys in _authorized_keys_paths(home_roots or ()):
        _emit("authorized_keys", keys)

    return observations


class PersistenceProbe(Probe):
    name = "persistence"
    description = "Fingerprints boot / device-event / login persistence points"

    def availability(self) -> ProbeAvailability:
        if Path("/etc").is_dir():
            return ProbeAvailability(ok=True)
        return ProbeAvailability(ok=False, detail="/etc not present")

    def snapshot(self) -> list[Observation]:
        return scan_persistence()
