# Copyright (c) 2026-present Stable State Consulting Ltd
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
from cableprobe.redact import redact_cmdline

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

from cableprobe.probes.base import Probe, ProbeAvailability

log = get_logger("probe.process")

#: comm prefixes of kernel worker/helper threads. Only used as a *fallback* for
#: hosts / containers where the parent pid does not read back as 2 (kthreadd),
#: and only together with an empty cmdline - a real kernel thread never has one,
#: so a userspace process that just names itself ``kworker/0:9`` is not excluded.
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


def _is_kernel_thread(
    pid: int | None, ppid: int | None, name: str | None, has_cmdline: bool
) -> bool:
    # Authoritative: a kernel thread is pid 2 (kthreadd) or a child of it. This
    # cannot be spoofed - you cannot reparent yourself onto pid 2.
    if pid in (0, 2) or ppid in (0, 2):
        return True
    # Fallback only when we could not read ppid, and only for a process with no
    # command line (every userspace process has one).
    if ppid is None and not has_cmdline:
        return bool(name and name.startswith(_KERNEL_THREAD_PREFIXES))
    return False


def _is_trivial_plumbing(name: str, cmdline: list[str]) -> bool:
    """``sleep 5`` / ``usleep 200`` - cron/shell glue with no room for a payload.

    Validated against the actual argv, so a process that merely *calls itself*
    ``sleep`` while doing something else is still reported.
    """

    if name in ("sleep", "usleep"):
        return (
            len(cmdline) == 2
            and cmdline[0].rsplit("/", 1)[-1] == name
            and cmdline[1].replace(".", "", 1).isdigit()
        )
    return False


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
        # cmdline is always needed for the kernel-thread / trivial-plumbing
        # checks; it is only *stored* when the operator asked for it.
        fields = ["pid", "name", "ppid", "username", "create_time", "cmdline"]

        own_pid = os.getpid()
        observations: list[Observation] = []
        for proc in psutil.process_iter(fields):
            try:
                info = proc.info
                created = info.get("create_time") or 0.0
                if created < self.session_start:
                    continue
                cmdline = info.get("cmdline") or []
                name = info.get("name") or ""
                if _is_kernel_thread(
                    info.get("pid"), info.get("ppid"), name, bool(cmdline)
                ):
                    continue
                # helper commands CableProbe itself shells out to (lsusb, ss,
                # journalctl, ...)
                if info.get("ppid") == own_pid:
                    continue
                if _is_trivial_plumbing(name, cmdline):
                    continue
                observations.append(
                    Observation(
                        kind=KIND_PROCESS,
                        identity=f"proc:{info['pid']}:{name or '?'}",
                        label=f"process {name or '?'} (pid {info['pid']})",
                        attributes={
                            "pid": info["pid"],
                            "ppid": info.get("ppid"),
                            "name": name or None,
                            "username": info.get("username"),
                            "cmdline": (
                                redact_cmdline(cmdline)
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
