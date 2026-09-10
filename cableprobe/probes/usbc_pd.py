# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""USB-C / USB Power Delivery state from ``/sys/class/typec``.

This is the one probe that is about the *cable and connector* rather than the
devices behind them. It records, for every Type-C port:

* the negotiated data role, power role and operating mode,
* whether a partner is attached and what it advertises (PD support, alt modes),
* alt modes entered on the port or the partner (DisplayPort, Thunderbolt, ...).

Signals worth a rule: a "charge only" cable that negotiates a **data** role, a
**data-role swap** mid-session, or **alt-mode entry** (DisplayPort / TBT) that
was not expected for the device under test.

Modern kernels expose this on Raspberry Pi 4/5 and most x86 laptops. On hosts
with no Type-C class directory the probe reports itself unavailable and is
skipped -- it is not an error.
"""

from __future__ import annotations

from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_USB_PD, Observation
from cableprobe.probes.base import Probe, ProbeAvailability

log = get_logger("probe.usbc_pd")

SYS_CLASS_TYPEC = "/sys/class/typec"

_PORT_FIELDS = (
    "data_role",
    "power_role",
    "port_type",
    "preferred_role",
    "power_operation_mode",
    "usb_power_delivery_revision",
    "usb_typec_revision",
    "vconn_source",
)

_PARTNER_FIELDS = (
    "supports_usb_power_delivery",
    "usb_power_delivery_revision",
    "type",
)


def _read(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None
    return value or None


def _role(value: str | None) -> str | None:
    """``[source] sink`` -> ``source`` (sysfs marks the active role with [])."""

    if not value:
        return value
    for token in value.split():
        if token.startswith("[") and token.endswith("]"):
            return token[1:-1]
    return value


def _alt_modes(node: Path) -> list[dict]:
    modes: list[dict] = []
    for child in sorted(node.iterdir()):
        if not child.is_dir() or not (child / "svid").exists():
            continue
        modes.append(
            {
                "name": child.name,
                "svid": _read(child / "svid"),
                "vdo": _read(child / "vdo"),
                "active": _read(child / "active"),
                "mode": _read(child / "mode"),
            }
        )
    return modes


def scan_typec(root: str = SYS_CLASS_TYPEC) -> list[Observation]:
    """Parse ``/sys/class/typec`` into USB-PD observations (ports + partners)."""

    base = Path(root)
    if not base.is_dir():
        return []

    observations: list[Observation] = []
    # Port nodes are ``port0``, ``port1``, ... ; exclude ``port0-partner`` and
    # the alt-mode subdirs ``port0.0`` / ``port0-partner.0``.
    ports = sorted(
        p
        for p in base.iterdir()
        if p.is_dir()
        and p.name.startswith("port")
        and "-" not in p.name
        and "." not in p.name
    )
    for port in ports:
        port_attrs: dict[str, object] = {}
        for field in _PORT_FIELDS:
            raw = _read(port / field)
            port_attrs[field] = _role(raw) if field.endswith("_role") else raw
        port_alt = _alt_modes(port)
        partner_dir = base / f"{port.name}-partner"
        partner_attached = partner_dir.is_dir()
        port_attrs["partner_attached"] = partner_attached
        port_attrs["port_alt_modes"] = [m["name"] for m in port_alt]

        observations.append(
            Observation(
                kind=KIND_USB_PD,
                identity=f"typec:{port.name}",
                label=(
                    f"USB-C {port.name}: data={port_attrs.get('data_role')} "
                    f"power={port_attrs.get('power_role')}"
                    + (" (partner attached)" if partner_attached else "")
                ),
                attributes=port_attrs,
            )
        )

        if partner_attached:
            partner_attrs: dict[str, object] = {"port": port.name}
            for field in _PARTNER_FIELDS:
                partner_attrs[field] = _read(partner_dir / field)
            identity_dir = partner_dir / "identity"
            if identity_dir.is_dir():
                partner_attrs["id_header"] = _read(identity_dir / "id_header")
                partner_attrs["product"] = _read(identity_dir / "product")
                partner_attrs["cert_stat"] = _read(identity_dir / "cert_stat")
            partner_alt = _alt_modes(partner_dir)
            partner_attrs["alt_modes"] = [m["name"] for m in partner_alt]
            partner_attrs["alt_modes_active"] = sorted(
                m["name"] for m in partner_alt if m.get("active") == "yes"
            )
            observations.append(
                Observation(
                    kind=KIND_USB_PD,
                    identity=f"typec:{port.name}-partner",
                    label=f"USB-C partner on {port.name}"
                    + (
                        f" (alt modes: {', '.join(partner_attrs['alt_modes'])})"
                        if partner_attrs["alt_modes"]
                        else ""
                    ),
                    attributes=partner_attrs,
                )
            )
    return observations


class UsbcPdProbe(Probe):
    name = "usbc_pd"
    description = "USB-C / Power Delivery port and partner state (roles, alt modes)"

    def availability(self) -> ProbeAvailability:
        base = Path(SYS_CLASS_TYPEC)
        if not base.is_dir():
            return ProbeAvailability(
                ok=False, detail=f"{SYS_CLASS_TYPEC} not present (no Type-C class)"
            )
        ports = [p for p in base.iterdir() if p.name.startswith("port")]
        if not ports:
            return ProbeAvailability(ok=False, detail="no Type-C ports exposed")
        return ProbeAvailability(ok=True, detail=f"{len(ports)} Type-C node(s)")

    def snapshot(self) -> list[Observation]:
        return scan_typec(SYS_CLASS_TYPEC)
