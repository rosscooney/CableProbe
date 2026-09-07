# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""CableProbe - defensive USB-C cable analysis tool.

CableProbe runs a controlled, three-phase test session (baseline / test /
post-test) while an unknown USB-C cable is connected to a sacrificial host
(typically a Raspberry Pi), then compares the phases and produces a structured
JSON report highlighting anything that appeared, disappeared or changed in
correlation with the cable being connected.

This is a *defensive* observation tool. It only watches, records and reports.
"""

__version__ = "0.1.0"
