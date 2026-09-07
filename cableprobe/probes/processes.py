# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Process inventory (only processes started after the session began).

Process churn is noisy, so this probe deliberately reports only *userspace*
processes whose creation time is at or after the session start. Kernel threads
(``kworker/*``, ``ksoftirqd/*``, ... - children of ``kthreadd``, pid 2) are
skipped: the kernel spawns, renames and reaps them constantly and none of that
correlates with a cable. A helper daemon spawning when a storage device is
auto-mounted, for example, would still show up here.
"""

from __future__ import annotations

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
