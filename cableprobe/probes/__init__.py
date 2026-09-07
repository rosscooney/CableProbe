# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""CableProbe observation probes.

Every probe is a small, mostly-independent unit that can:

* report whether it can run on this host (:meth:`Probe.availability`),
* start / stop any background monitoring,
* produce a point-in-time :class:`~cableprobe.models.Observation` list
  (:meth:`Probe.snapshot`),
* drain asynchronous :class:`~cableprobe.models.ProbeEvent` objects that
  occurred since the last drain (:meth:`Probe.drain_events`).

Probes must never modify the system. They only read.
"""

from cableprobe.probes.base import Probe, ProbeAvailability
from cableprobe.probes.registry import PROBE_REGISTRY, build_probes

__all__ = ["Probe", "ProbeAvailability", "PROBE_REGISTRY", "build_probes"]
