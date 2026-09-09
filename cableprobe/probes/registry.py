# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Probe registry and factory."""

from __future__ import annotations

from cableprobe.config import Config
from cableprobe.logging_config import get_logger
from cableprobe.probes.base import Probe
from cableprobe.probes.block import BlockDeviceProbe
from cableprobe.probes.connections import ConnectionProbe
from cableprobe.probes.hid_report import HidReportProbe
from cableprobe.probes.input_devices import InputDeviceProbe
from cableprobe.probes.kernel_log import KernelLogProbe
from cableprobe.probes.keystroke_cadence import KeystrokeCadenceProbe
from cableprobe.probes.media_devices import AudioDeviceProbe, VideoDeviceProbe
from cableprobe.probes.network import NetworkInterfaceProbe
from cableprobe.probes.network_state import ListenerProbe, RoutingProbe
from cableprobe.probes.persistence import PersistenceProbe
from cableprobe.probes.power import PowerProbe
from cableprobe.probes.processes import ProcessProbe
from cableprobe.probes.serial_devices import SerialDeviceProbe
from cableprobe.probes.system_state import (
    KernelModuleProbe,
    MountProbe,
    PciDeviceProbe,
)
from cableprobe.probes.udev_monitor import UdevMonitorProbe
from cableprobe.probes.usb import UsbProbe
from cableprobe.probes.usb_sysfs import UsbDescriptorProbe, UsbTopologyProbe
from cableprobe.probes.usbc_pd import UsbcPdProbe
from cableprobe.probes.wifi_scan import WifiScanProbe

log = get_logger("probe.registry")

_PROBE_CLASSES: tuple[type[Probe], ...] = (
    UdevMonitorProbe,
    UsbProbe,
    UsbDescriptorProbe,
    UsbTopologyProbe,
    HidReportProbe,
    UsbcPdProbe,
    BlockDeviceProbe,
    MountProbe,
    NetworkInterfaceProbe,
    RoutingProbe,
    ListenerProbe,
    ConnectionProbe,
    PersistenceProbe,
    InputDeviceProbe,
    SerialDeviceProbe,
    AudioDeviceProbe,
    VideoDeviceProbe,
    PciDeviceProbe,
    KernelModuleProbe,
    WifiScanProbe,
    PowerProbe,
    KeystrokeCadenceProbe,
    ProcessProbe,
    KernelLogProbe,
)

PROBE_REGISTRY: dict[str, type[Probe]] = {cls.name: cls for cls in _PROBE_CLASSES}


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
