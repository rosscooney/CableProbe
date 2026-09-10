# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Best-effort host information for the session report."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import Any

try:  # psutil is a hard dependency, but keep this resilient
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]


def _raspberry_pi_model() -> str | None:
    for candidate in ("/proc/device-tree/model", "/sys/firmware/devicetree/base/model"):
        try:
            text = Path(candidate).read_bytes().decode("utf-8", "ignore").strip("\x00").strip()
            if text:
                return text
        except OSError:
            continue
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    for line in cpuinfo.splitlines():
        if line.lower().startswith("model") and ":" in line:
            return line.split(":", 1)[1].strip() or None
    return None


def collect_host_info() -> dict[str, Any]:
    uname = platform.uname()
    info: dict[str, Any] = {
        "system": uname.system,
        "node": uname.node,
        "release": uname.release,
        "version": uname.version,
        "machine": uname.machine,
        "python_version": sys.version.split()[0],
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "running_as_root": (os.geteuid() == 0) if hasattr(os, "geteuid") else None,
    }

    model = _raspberry_pi_model()
    if model:
        info["hardware_model"] = model

    if psutil is not None:
        try:
            info["boot_time"] = psutil.boot_time()
        except (OSError, RuntimeError, NotImplementedError):  # pragma: no cover
            pass
        try:
            info["cpu_count"] = psutil.cpu_count()
        except (OSError, RuntimeError, NotImplementedError):  # pragma: no cover
            pass

    return info
