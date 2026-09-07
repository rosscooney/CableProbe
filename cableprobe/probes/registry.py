# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Probe registry and factory."""

from __future__ import annotations

from cableprobe.config import Config
from cableprobe.logging_config import get_logger
from cableprobe.probes.base import Probe
from cableprobe.probes.block import BlockDeviceProbe
from cableprobe.probes.input_devices import InputDeviceProbe
from cableprobe.probes.kernel_log import KernelLogProbe
from cableprobe.probes.network import NetworkInterfaceProbe
from cableprobe.probes.processes import ProcessProbe
from cableprobe.probes.udev_monitor import UdevMonitorProbe
from cableprobe.probes.usb import UsbProbe

log = get_logger("probe.registry")

PROBE_REGISTRY: dict[str, type[Probe]] = {
    UdevMonitorProbe.name: UdevMonitorProbe,
    UsbProbe.name: UsbProbe,
    BlockDeviceProbe.name: BlockDeviceProbe,
    NetworkInterfaceProbe.name: NetworkInterfaceProbe,
    InputDeviceProbe.name: InputDeviceProbe,
    ProcessProbe.name: ProcessProbe,
    KernelLogProbe.name: KernelLogProbe,
}


def build_probes(config: Config, session_start: float) -> list[Probe]:
    """Instantiate the probes named in ``config.probes.enabled`` (in order)."""

    probes: list[Probe] = []
    for name in config.probes.enabled:
        probe_cls = PROBE_REGISTRY.get(name)
        if probe_cls is None:
            log.warning("unknown probe %r in configuration - skipping", name)
            continue
        probes.append(probe_cls(config=config, session_start=session_start))
    return probes
