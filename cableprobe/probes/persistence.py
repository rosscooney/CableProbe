# Copyright (c) 2026 Stable State Consulting Ltd
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


def _hash_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return None


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
        digest = _hash_file(path)
        try:
            size = path.stat().st_size
        except OSError:
            size = None
        observations.append(
            Observation(
                kind=KIND_PERSISTENCE_ITEM,
                identity=f"persist:{key}",
                label=f"{label}: {key}",
                attributes={
                    "path": key,
                    "category": label,
                    "sha256_16": digest,
                    "size": size,
                    "present": digest is not None,
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
    samples_periodically = False

    def availability(self) -> ProbeAvailability:
        if Path("/etc").is_dir():
            return ProbeAvailability(ok=True)
        return ProbeAvailability(ok=False, detail="/etc not present")

    def snapshot(self) -> list[Observation]:
        return scan_persistence()
