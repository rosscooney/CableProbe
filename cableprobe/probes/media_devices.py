# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Audio and video capture device inventory.

A USB-C cable that enumerates a microphone (USB audio class) or a camera (USB
video class / UVC) is almost never a plain charge/data cable -- both are covert
capture vectors, and audio-class devices are also a common camouflage for other
interfaces.

``audio`` reads the ``sound`` udev subsystem (or ``/proc/asound/cards``).
``video`` reads the ``video4linux`` udev subsystem (or ``/sys/class/video4linux``).
"""

from __future__ import annotations

import re
from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_AUDIO_DEVICE, KIND_VIDEO_DEVICE, Observation
from cableprobe.probes.base import (
    Probe,
    ProbeAvailability,
    sysfs_device_is_usb,
    sysfs_driver,
    udev_context,
)

try:  # pragma: no cover - platform dependent
    import pyudev
except Exception:  # noqa: BLE001
    pyudev = None  # type: ignore[assignment]

log = get_logger("probe.media")

PROC_ASOUND_CARDS = "/proc/asound/cards"
SYS_CLASS_V4L = "/sys/class/video4linux"

_ASOUND_CARD = re.compile(
    r"^\s*(?P<idx>\d+)\s+\[(?P<id>[^\]]+)\]:\s*(?P<driver>\S+)\s*-\s*(?P<name>.+)$"
)


# --------------------------------------------------------------------------
# audio
# --------------------------------------------------------------------------


def parse_asound_cards(text: str) -> list[Observation]:
    """Parse ``/proc/asound/cards`` into audio-device observations."""

    observations: list[Observation] = []
    for line in text.splitlines():
        match = _ASOUND_CARD.match(line)
        if not match:
            continue
        card_id = match.group("id").strip()
        driver = match.group("driver").strip()
        name = match.group("name").strip()
        is_usb = "usb" in f"{driver} {name}".lower()
        observations.append(
            Observation(
                kind=KIND_AUDIO_DEVICE,
                identity=f"sound:{card_id}",
                label=f"audio device: {name}",
                attributes={
                    "card": card_id,
                    "index": match.group("idx"),
                    "driver": driver,
                    "name": name,
                    "is_usb": is_usb,
                    "source": "proc",
                },
            )
        )
    return observations


def _audio_from_udev(device) -> Observation | None:
    # One card has many nodes (controlC0, pcmC0D0p, ...). Only the ``cardN``
    # node carries the card-level identity; skip the rest.
    match = re.search(r"card(\d+)", device.sys_name or "")
    if not match:
        return None
    card_no = match.group(1)
    id_path = device.get("ID_PATH", "")
    is_usb = device.get("ID_BUS") == "usb" or "usb" in id_path.lower()
    name = (
        device.get("ID_MODEL_FROM_DATABASE")
        or device.get("ID_MODEL")
        or device.get("ID_ID")
        or f"card {card_no}"
    )
    return Observation(
        kind=KIND_AUDIO_DEVICE,
        identity=f"sound:card{card_no}",
        label=f"audio device: {name}",
        attributes={
            "card": f"card{card_no}",
            "name": str(name),
            "vendor_id": device.get("ID_VENDOR_ID"),
            "product_id": device.get("ID_MODEL_ID"),
            "vendor": device.get("ID_VENDOR_FROM_DATABASE") or device.get("ID_VENDOR"),
            "is_usb": bool(is_usb),
            "source": "pyudev",
        },
    )


class AudioDeviceProbe(Probe):
    name = "audio"
    description = "Inventory of audio (sound-card) devices, including USB audio"

    def availability(self) -> ProbeAvailability:
        if pyudev is not None:
            return ProbeAvailability(ok=True, detail="using pyudev")
        if Path(PROC_ASOUND_CARDS).exists():
            return ProbeAvailability(ok=True, detail=f"using {PROC_ASOUND_CARDS}")
        return ProbeAvailability(ok=False, detail="no pyudev and no /proc/asound/cards")

    def snapshot(self) -> list[Observation]:
        if pyudev is not None:
            try:
                context = udev_context()
                seen: dict[str, Observation] = {}
                for device in context.list_devices(subsystem="sound"):
                    obs = _audio_from_udev(device)
                    if obs is None:
                        continue
                    # Prefer the richest record per card.
                    if obs.identity not in seen or len(obs.attributes) > len(
                        seen[obs.identity].attributes
                    ):
                        seen[obs.identity] = obs
                if seen:
                    return list(seen.values())
            except Exception as exc:  # noqa: BLE001  # pragma: no cover
                log.warning("pyudev sound enumeration failed (%s); trying /proc", exc)

        path = Path(PROC_ASOUND_CARDS)
        if not path.exists():
            raise RuntimeError(f"{PROC_ASOUND_CARDS} not present")
        return parse_asound_cards(path.read_text(encoding="utf-8", errors="ignore"))


# --------------------------------------------------------------------------
# video
# --------------------------------------------------------------------------


def scan_sysfs_v4l(root: str = SYS_CLASS_V4L) -> list[Observation]:
    """Parse ``/sys/class/video4linux`` into video-device observations."""

    base = Path(root)
    if not base.is_dir():
        return []
    observations: list[Observation] = []
    for entry in sorted(base.iterdir()):
        name_file = entry / "name"
        try:
            human = name_file.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            human = entry.name
        observations.append(
            Observation(
                kind=KIND_VIDEO_DEVICE,
                identity=f"v4l:{entry.name}",
                label=f"video device /dev/{entry.name}: {human}",
                attributes={
                    "name": entry.name,
                    "devname": f"/dev/{entry.name}",
                    "human_name": human,
                    "driver": sysfs_driver(entry),
                    "is_usb": sysfs_device_is_usb(entry),
                    "source": "sysfs",
                },
            )
        )
    return observations


def _video_from_udev(device) -> Observation:
    name = device.sys_name
    human = device.get("ID_V4L_PRODUCT") or device.get("ID_MODEL") or name
    is_usb = device.get("ID_BUS") == "usb" or device.get("ID_USB_INTERFACES") is not None
    return Observation(
        kind=KIND_VIDEO_DEVICE,
        identity=f"v4l:{name}",
        label=f"video device /dev/{name}: {human}",
        attributes={
            "name": name,
            "devname": device.get("DEVNAME") or f"/dev/{name}",
            "human_name": str(human),
            "vendor_id": device.get("ID_VENDOR_ID"),
            "product_id": device.get("ID_MODEL_ID"),
            "vendor": device.get("ID_VENDOR_FROM_DATABASE") or device.get("ID_VENDOR"),
            "capabilities": device.get("ID_V4L_CAPABILITIES"),
            "is_usb": bool(is_usb),
            "source": "pyudev",
        },
    )


class VideoDeviceProbe(Probe):
    name = "video"
    description = "Inventory of video4linux (camera / capture) devices, including UVC"

    def availability(self) -> ProbeAvailability:
        if pyudev is not None:
            return ProbeAvailability(ok=True, detail="using pyudev")
        if Path(SYS_CLASS_V4L).is_dir():
            return ProbeAvailability(ok=True, detail=f"using {SYS_CLASS_V4L}")
        return ProbeAvailability(
            ok=False, detail="no pyudev and no /sys/class/video4linux"
        )

    def snapshot(self) -> list[Observation]:
        if pyudev is not None:
            try:
                context = udev_context()
                out = [
                    _video_from_udev(device)
                    for device in context.list_devices(subsystem="video4linux")
                ]
                if out:
                    return out
            except Exception as exc:  # noqa: BLE001  # pragma: no cover
                log.warning("pyudev v4l enumeration failed (%s); trying sysfs", exc)
        return scan_sysfs_v4l()
