# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Process inventory (only processes started after the session began).

Process churn is noisy, so this probe deliberately reports only processes whose
creation time is at or after the session start. A helper daemon spawning when a
storage device is auto-mounted, for example, would show up here.
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


class ProcessProbe(Probe):
    name = "process"
    description = "New processes started since the session began"

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
