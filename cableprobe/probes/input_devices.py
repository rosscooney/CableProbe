# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Input (HID) device inventory.

The single most important BadUSB-style signal: a keyboard, mouse or other HID
device that appears only while the unknown cable is connected.

Uses pyudev's ``ID_INPUT_*`` properties when available, otherwise parses
``/proc/bus/input/devices``.
"""

from __future__ import annotations

from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_INPUT_DEVICE, Observation
from cableprobe.probes.base import Probe, ProbeAvailability, udev_context

try:  # pragma: no cover - platform dependent
    import pyudev
except ImportError:
    pyudev = None  # type: ignore[assignment]

log = get_logger("probe.input")

PROC_INPUT_DEVICES = "/proc/bus/input/devices"

_CAPABILITY_HANDLERS = {
    "kbd": "keyboard",
    "mouse": "mouse",
    "leds": "leds",
    "js": "joystick",
}


def parse_proc_input(text: str) -> list[Observation]:
    """Parse ``/proc/bus/input/devices`` into observations."""

    observations: list[Observation] = []
    block: dict[str, str] = {}

    def flush() -> None:
        if not block:
            return
        name = block.get("N", "").split('Name="')[-1].strip('"') or "input device"
        ident_bits = block.get("I", "")
        sysfs = block.get("S", "").replace("Sysfs=", "").strip()
        handlers = block.get("H", "").replace("Handlers=", "").strip().split()
        vendor = product = None
        for token in ident_bits.split():
            if token.startswith("Vendor="):
                vendor = token.split("=", 1)[1]
            elif token.startswith("Product="):
                product = token.split("=", 1)[1]
        identity = sysfs or f"input:{vendor}:{product}:{name}"
        is_keyboard = any(h.startswith("kbd") for h in handlers)
        capabilities = sorted(
            {
                _CAPABILITY_HANDLERS[h.rstrip("0123456789")]
                for h in handlers
                if h.rstrip("0123456789") in _CAPABILITY_HANDLERS
            }
        )
        observations.append(
            Observation(
                kind=KIND_INPUT_DEVICE,
                identity=identity,
                label=f"input device: {name}",
                attributes={
                    "name": name,
                    "vendor_id": vendor,
                    "product_id": product,
                    "sysfs": sysfs,
                    "handlers": handlers,
                    "capabilities": capabilities,
                    "ID_INPUT_KEYBOARD": "1" if is_keyboard else None,
                    "ID_INPUT_MOUSE": "1" if ("mouse" in capabilities) else None,
                    "source": "proc",
                },
            )
        )
        block.clear()

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            flush()
            continue
        if len(line) >= 2 and line[1] == ":":
            tag = line[0]
            value = line[3:].strip()
            block[tag] = (block.get(tag, "") + " " + value).strip() if tag in block else value
    flush()
    return observations


def _observation_from_udev(device) -> Observation:
    name = device.get("NAME", "").strip('"') or device.get("ID_MODEL") or device.sys_name
    identity = device.get("DEVPATH") or device.sys_path or f"input:{device.sys_name}"
    keyboard = device.get("ID_INPUT_KEYBOARD")
    mouse = device.get("ID_INPUT_MOUSE")
    caps = [
        cap
        for cap, key in (
            ("keyboard", "ID_INPUT_KEYBOARD"),
            ("mouse", "ID_INPUT_MOUSE"),
            ("touchpad", "ID_INPUT_TOUCHPAD"),
            ("tablet", "ID_INPUT_TABLET"),
            ("joystick", "ID_INPUT_JOYSTICK"),
        )
        if device.get(key) == "1"
    ]
    return Observation(
        kind=KIND_INPUT_DEVICE,
        identity=str(identity),
        label=f"input device: {name}",
        attributes={
            "name": str(name),
            "vendor_id": device.get("ID_VENDOR_ID"),
            "product_id": device.get("ID_MODEL_ID"),
            "capabilities": caps,
            "ID_INPUT_KEYBOARD": keyboard,
            "ID_INPUT_MOUSE": mouse,
            "is_usb": (device.get("ID_BUS") == "usb"),
            "devname": device.get("DEVNAME"),
            "source": "pyudev",
        },
    )


def _usb_parent_key(device) -> str | None:
    """The sysfs name of the USB device an input node hangs off (``1-1.2``)."""

    try:
        parent = device.find_parent("usb", "usb_device")
    except Exception as exc:  # noqa: BLE001  # pragma: no cover - pyudev quirks
        log.debug("find_parent(usb) failed for %s: %s", device, exc)
        parent = None
    return parent.sys_name if parent is not None else None


def _merge_input_group(key: str, members: list[Observation]) -> Observation:
    """Collapse the input collections of one USB device into one observation."""

    if len(members) == 1:
        return members[0]

    primary = min(members, key=lambda o: len(str(o.attributes.get("name") or o.label)))
    caps = sorted(
        {c for m in members for c in (m.attributes.get("capabilities") or [])}
    )
    collections = sorted(
        {str(m.attributes.get("name") or "").strip() for m in members} - {""}
    )

    def _any_flag(flag: str) -> str | None:
        return "1" if any(m.attributes.get(flag) == "1" for m in members) else None

    attrs = dict(primary.attributes)
    attrs.update(
        {
            "capabilities": caps,
            "ID_INPUT_KEYBOARD": _any_flag("ID_INPUT_KEYBOARD"),
            "ID_INPUT_MOUSE": _any_flag("ID_INPUT_MOUSE"),
            "collections": collections,
            "collection_count": len(members),
        }
    )
    name = str(primary.attributes.get("name") or primary.label)
    return Observation(
        kind=KIND_INPUT_DEVICE,
        identity=f"input:usb:{key}",
        label=f"input device: {name}",
        attributes=attrs,
    )


class InputDeviceProbe(Probe):
    name = "input"
    description = "Inventory of input/HID devices (keyboards, mice, tablets)"

    def availability(self) -> ProbeAvailability:
        if pyudev is not None:
            return ProbeAvailability(ok=True, detail="using pyudev")
        if Path(PROC_INPUT_DEVICES).exists():
            return ProbeAvailability(ok=True, detail=f"using {PROC_INPUT_DEVICES}")
        return ProbeAvailability(ok=False, detail="no pyudev and no /proc/bus/input/devices")

    def snapshot(self) -> list[Observation]:
        if pyudev is not None:
            try:
                context = udev_context()
                singles: dict[str, Observation] = {}
                groups: dict[str, list[Observation]] = {}
                for device in context.list_devices(subsystem="input"):
                    # The "input" subsystem lists both the logical "inputN"
                    # devices and their "eventN" / "mouseN" / "jsN" char-device
                    # children - the same physical device twice, with slightly
                    # different names. Keep only the logical node.
                    if not (device.sys_name or "").startswith("input"):
                        continue
                    if device.get("ID_INPUT") != "1" and not device.get("NAME"):
                        continue
                    obs = _observation_from_udev(device)
                    # One physical USB keyboard / mouse often exposes several
                    # "inputN" collections (keyboard + consumer-control + system
                    # -control). Merge them into one observation per USB device
                    # so it reads as "a keyboard appeared", not three findings.
                    key = _usb_parent_key(device)
                    if key is None:
                        singles.setdefault(obs.identity, obs)
                    else:
                        groups.setdefault(key, []).append(obs)
                out = list(singles.values())
                out.extend(_merge_input_group(k, m) for k, m in groups.items())
                if out:
                    return out
            except Exception as exc:  # noqa: BLE001  # pragma: no cover
                log.warning("pyudev input enumeration failed: %s", exc)

        path = Path(PROC_INPUT_DEVICES)
        if not path.exists():
            raise RuntimeError(f"{PROC_INPUT_DEVICES} not present")
        return parse_proc_input(path.read_text(encoding="utf-8", errors="ignore"))
