# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""CableProbe - defensive USB cable analysis tool.

CableProbe runs a controlled, three-phase test session (baseline / test /
post-test) while an unknown USB cable (USB-C or USB-A) is connected to a
sacrificial host (typically a Raspberry Pi), then compares the phases and
produces a structured JSON report highlighting anything that appeared,
disappeared or changed in correlation with the cable being connected.

This is a *defensive* observation tool. It only watches, records and reports.
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("cableprobe")
except PackageNotFoundError:  # running from a source tree that isn't installed
    __version__ = "0.0.0+dev"

__all__ = ["__version__"]
