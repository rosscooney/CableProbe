# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Process inventory (only processes started after the session began).

Process churn is noisy, so this probe deliberately reports only *userspace*
processes whose creation time is at or after the session start, and drops:

* kernel threads (``kworker/*``, ``ksoftirqd/*``, ... - children of
  ``kthreadd``), which the kernel spawns, renames and reaps constantly;
* the helper commands CableProbe itself shells out to (``lsusb``, ``ss``,
  ``journalctl``, ...);
* trivial cron / systemd / shell plumbing (``sleep``, ``flock``, ...).

A helper daemon spawning when a storage device is auto-mounted, or
ModemManager probing a rogue serial gadget, still shows up here.
"""

from __future__ import annotations

import os

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_PROCESS, Observation

try:
    import psutil
except Exception:  # pragma: no cover - defensive
    psutil = None  # type: ignore[assignment]

from cableprobe.probes.base import Probe, ProbeAvailability

log = get_logger("probe.process")

#: comm prefixes of kernel worker/helper threads, as a fallback for hosts where
#: the parent pid does not read back as 2 (kthreadd).
_KERNEL_THREAD_PREFIXES = (
    "kworker/",
    "ksoftirqd/",
    "migration/",
    "rcu_",
    "irq/",
    "cpuhp/",
    "watchdog/",
    "idle_inject/",
    "kdevtmpfs",
    "kswapd",
    "kcompactd",
    "khugepaged",
)


def _is_kernel_thread(pid: int | None, ppid: int | None, name: str | None) -> bool:
    if pid in (0, 2) or ppid in (0, 2):
        return True
    return bool(name and name.startswith(_KERNEL_THREAD_PREFIXES))


#: Trivial helper commands that show up constantly in cron / systemd / shell
#: plumbing and never carry a cable signal on their own.
_NOISE_PROCESS_NAMES = {"sleep", "usleep", "flock", "run-parts"}


class ProcessProbe(Probe):
    name = "process"
    description = "New userspace processes started since the session began"

    def availability(self) -> ProbeAvailability:
        if psutil is None:
            return ProbeAvailability(ok=False, detail="psutil not available")
        return ProbeAvailability(ok=True)

    def snapshot(self) -> list[Observation]:
        if psutil is None:
            raise RuntimeError("psutil not available")

        capture_cmdline = self.config.probes.capture_process_cmdline
        fields = ["pid", "name", "ppid", "username", "create_time"]
        if capture_cmdline:
            fields.append("cmdline")

        own_pid = os.getpid()
        observations: list[Observation] = []
        for proc in psutil.process_iter(fields):
            try:
                info = proc.info
                created = info.get("create_time") or 0.0
                if created < self.session_start:
                    continue
                if _is_kernel_thread(
                    info.get("pid"), info.get("ppid"), info.get("name")
                ):
                    continue
                # helper commands CableProbe itself shells out to (lsusb, ss,
                # journalctl, ...) and trivial cron/systemd plumbing
                if info.get("ppid") == own_pid:
                    continue
                if (info.get("name") or "") in _NOISE_PROCESS_NAMES:
                    continue
                cmdline = info.get("cmdline") or []
                observations.append(
                    Observation(
                        kind=KIND_PROCESS,
                        identity=f"proc:{info['pid']}:{info.get('name') or '?'}",
                        label=f"process {info.get('name') or '?'} (pid {info['pid']})",
                        attributes={
                            "pid": info["pid"],
                            "ppid": info.get("ppid"),
                            "name": info.get("name"),
                            "username": info.get("username"),
                            "cmdline": (
                                " ".join(cmdline)
                                if (capture_cmdline and cmdline)
                                else None
                            ),
                            "create_time": created,
                        },
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):  # pragma: no cover
                continue
        return observations
