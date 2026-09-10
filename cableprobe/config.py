# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Configuration models for CableProbe.

Configuration is layered:

1. Built-in defaults (this module).
2. An optional YAML config file (``--config``).
3. Command-line overrides.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

#: Probe names enabled by default, in a sensible ordering.
#:
#: ``wifi_scan`` is deliberately NOT here: on any premises with Wi-Fi it produces
#: a dozen-plus deltas per session (neighbouring APs drift in and out of scan
#: range on their own) and it is only meaningful when you specifically suspect
#: the cable carries a radio *and* can baseline somewhere RF-quiet. Enable it
#: explicitly for that investigation.
DEFAULT_PROBES: list[str] = [
    "udev_monitor",
    "usb",
    "usb_descriptors",
    "usb_topology",
    "hid_report",
    "usbc_pd",
    "block",
    "mounts",
    "network",
    "routing",
    "listeners",
    "persistence",
    "input",
    "serial",
    "audio",
    "video",
    "pci",
    "kernel_modules",
    "keystroke_cadence",
    "process",
    "kernel_log",
]

#: Probes that exist but are off by default:
#:   wifi_scan    - noisy on premises with Wi-Fi
#:   power        - needs an INA219 wired up + the ``power`` extra
#:   connections  - noisy unless the test host has NO internet access
OPTIONAL_PROBES: list[str] = ["wifi_scan", "power", "connections"]


class SessionConfig(BaseModel):
    """Timing and interaction settings for a test session."""

    baseline_seconds: int = 30
    test_seconds: int = 60
    post_test_seconds: int = 30
    #: How often, within a phase, to drain queued probe events and refresh the
    #: progress display. Snapshots themselves are taken only at phase boundaries.
    sample_interval_seconds: float = 2.0
    interactive: bool = True
    auto_advance_grace_seconds: int = 5

    @field_validator(
        "baseline_seconds",
        "test_seconds",
        "post_test_seconds",
    )
    @classmethod
    def _positive_phase(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("phase durations must be greater than zero seconds")
        return value

    @field_validator("sample_interval_seconds")
    @classmethod
    def _positive_interval(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("sample_interval_seconds must be greater than zero")
        return value


class ProbeConfig(BaseModel):
    enabled: list[str] = Field(default_factory=lambda: list(DEFAULT_PROBES))
    #: Kernel-log backend: ``auto`` | ``journalctl`` | ``dmesg``.
    kernel_log_backend: str = "auto"
    #: Extra keyword filters for kernel-log lines (case-insensitive substring).
    kernel_log_keywords: list[str] = Field(default_factory=list)
    #: Keep routine USB enumeration chatter ("New USB device found", "Product:",
    #: link-speed lines) in the kernel-log probe. Off by default -- the usb /
    #: input / usb_descriptors probes already carry that, structured.
    kernel_log_verbose: bool = False
    #: Record full process command lines in the report. Command lines can carry
    #: secrets (e.g. passwords passed as arguments); set false to store only the
    #: executable name.
    capture_process_cmdline: bool = True
    #: Let the keystroke_cadence probe read /dev/input/event* for key-press
    #: *timing* (never key identity). Set false to disable that probe entirely.
    capture_keystroke_timing: bool = True
    #: `power` probe (INA219 over I2C) settings.
    power_i2c_bus: int = 1
    power_i2c_address: int = 0x40
    power_shunt_ohms: float = 0.1
    #: mA above the no-cable baseline that counts as "there is powered
    #: electronics in the cable".
    power_alert_ma: int = 8

    @field_validator("kernel_log_backend")
    @classmethod
    def _known_backend(cls, value: str) -> str:
        allowed = {"auto", "journalctl", "dmesg"}
        if value not in allowed:
            raise ValueError(f"kernel_log_backend must be one of {sorted(allowed)}")
        return value


class Config(BaseModel):
    session: SessionConfig = Field(default_factory=SessionConfig)
    probes: ProbeConfig = Field(default_factory=ProbeConfig)
    #: Optional path to a YAML rules file. ``None`` means "use packaged defaults".
    rules_file: Path | None = None
    #: Extra known-implant VID/PID YAML file, merged with the packaged list.
    implants_file: Path | None = None
    #: YAML allowlist of devices you trust; their findings are downgraded to
    #: info. ``None`` -> ``<output_dir>/allowlist.yaml`` if it exists.
    allowlist_file: Path | None = None
    output_dir: Path = Path("./cableprobe-sessions")

    model_config = {"extra": "forbid"}

    @classmethod
    def load(cls, path: Path | str | None) -> "Config":
        """Load configuration from a YAML file, or return defaults if ``path`` is None."""

        if path is None:
            return cls()
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"config file not found: {path}")
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise ValueError("config file must contain a YAML mapping at the top level")
        return cls.model_validate(raw)

    def as_metadata(self) -> dict[str, Any]:
        """A JSON-serialisable snapshot of the effective config for the report."""

        return self.model_dump(mode="json")
