# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Structured (Pydantic) models shared across CableProbe.

The observation model is deliberately *generic*: every probe emits the same
``Observation`` / ``ProbeEvent`` shape, keyed by ``(kind, identity)``. This lets
the analysis and rules engines treat USB devices, network interfaces, input
devices, block devices, kernel messages and processes uniformly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from cableprobe.sanitize import IDENTITY_MAX_LEN, clean_attributes, clean_text

# --- phase names -----------------------------------------------------------

PHASE_BASELINE = "baseline"
PHASE_TEST = "test"
PHASE_POST_TEST = "post_test"
PHASE_ORDER = (PHASE_BASELINE, PHASE_TEST, PHASE_POST_TEST)

# --- observation kinds ----------------------------------------------------

KIND_USB_DEVICE = "usb_device"
KIND_USB_INTERFACE = "usb_interface"
KIND_USB_DESCRIPTOR = "usb_descriptor"
KIND_USB_PD = "usb_pd"
KIND_USB_TOPOLOGY = "usb_topology"
KIND_HID_REPORT = "hid_report"
KIND_BLOCK_DEVICE = "block_device"
KIND_NETWORK_INTERFACE = "network_interface"
KIND_NETWORK_CONFIG = "network_config"
KIND_LISTENING_SOCKET = "listening_socket"
KIND_INPUT_DEVICE = "input_device"
KIND_HID_DEVICE = "hid_device"
KIND_SERIAL_DEVICE = "serial_device"
KIND_AUDIO_DEVICE = "audio_device"
KIND_VIDEO_DEVICE = "video_device"
KIND_PCI_DEVICE = "pci_device"
KIND_KERNEL_MODULE = "kernel_module"
KIND_MOUNT = "mount"
KIND_OUTBOUND_CONNECTION = "outbound_connection"
KIND_PERSISTENCE_ITEM = "persistence_item"
KIND_WIFI_AP = "wifi_ap"
KIND_KEYSTROKE_TIMING = "keystroke_timing"
KIND_POWER_READING = "power_reading"
KIND_PROCESS = "process"
KIND_KERNEL_MESSAGE = "kernel_message"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


Scalar = str | int | float | bool | None


class Observation(BaseModel):
    """A single thing observed on the host at a point in time."""

    kind: str
    #: Stable-ish key used to correlate the same thing across phases.
    identity: str
    #: Human-readable one-liner.
    label: str
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("kind", "identity", "label")
    @classmethod
    def _clean_str_fields(cls, value: str, info) -> str:
        limit = IDENTITY_MAX_LEN if info.field_name == "identity" else 300
        return clean_text(value, max_len=limit)

    @field_validator("attributes")
    @classmethod
    def _clean_attrs(cls, value: dict[str, Any]) -> dict[str, Any]:
        return clean_attributes(value)

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind, self.identity)


class ProbeEvent(BaseModel):
    """An asynchronous event captured while a phase was running (e.g. udev add)."""

    timestamp: datetime
    probe: str
    action: str  # add | remove | change | bind | unbind | move | online | offline
    kind: str
    identity: str
    label: str
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action", "kind", "identity", "label")
    @classmethod
    def _clean_str_fields(cls, value: str, info) -> str:
        limit = IDENTITY_MAX_LEN if info.field_name == "identity" else 300
        return clean_text(value, max_len=limit)

    @field_validator("attributes")
    @classmethod
    def _clean_attrs(cls, value: dict[str, Any]) -> dict[str, Any]:
        return clean_attributes(value)


class SystemSnapshot(BaseModel):
    """The full set of observations captured in one sampling pass."""

    timestamp: datetime = Field(default_factory=utcnow)
    observations: list[Observation] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def index(self) -> dict[tuple[str, str], Observation]:
        return {obs.key: obs for obs in self.observations}


class PhaseObservation(BaseModel):
    phase: str
    started_at: datetime
    ended_at: datetime
    start_snapshot: SystemSnapshot
    end_snapshot: SystemSnapshot
    events: list[ProbeEvent] = Field(default_factory=list)


class AttributeChange(BaseModel):
    key: str
    before: Any
    after: Any


class Delta(BaseModel):
    """A difference between phases for one ``(kind, identity)``."""

    change: str  # appeared | disappeared | modified
    kind: str
    identity: str
    label: str
    first_seen_phase: str | None = None
    present_in: dict[str, bool] = Field(default_factory=dict)
    #: For things that appeared during TEST: did they go away after disconnect?
    reverted_after_disconnect: bool | None = None
    #: True if only seen via a transient event, never in an end-of-phase snapshot.
    transient: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)
    attribute_changes: list[AttributeChange] = Field(default_factory=list)
    #: Related asynchronous events, for evidence.
    related_events: list[ProbeEvent] = Field(default_factory=list)


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: str  # info | low | medium | high | critical
    rationale: str = ""
    evidence: list[str] = Field(default_factory=list)
    related_identities: list[str] = Field(default_factory=list)


class SessionMetadata(BaseModel):
    session_name: str
    cableprobe_version: str
    started_at: datetime
    ended_at: datetime
    interactive: bool
    host: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    probes_used: list[str] = Field(default_factory=list)
    #: Probes skipped because the host does not expose the needed interface
    #: (no Type-C class, no /sys/bus/pci, ...). Expected, not a problem.
    probes_unavailable: list[str] = Field(default_factory=list)
    #: Probes that were enabled and available but misbehaved (failed to start).
    probe_warnings: list[str] = Field(default_factory=list)


class SessionReport(BaseModel):
    metadata: SessionMetadata
    phases: dict[str, PhaseObservation]
    deltas: list[Delta] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)

    def to_json(self, *, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)
