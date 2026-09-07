# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Block device inventory via ``lsblk -J``.

A USB-C cable that causes a new mass-storage device to enumerate is a strong
signal, so transport (``tran``) and hotplug status are recorded.
"""

from __future__ import annotations

import json
from typing import Any

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_BLOCK_DEVICE, Observation
from cableprobe.probes.base import Probe, ProbeAvailability, have_tool, run_command

log = get_logger("probe.block")

_COLUMNS = "NAME,PATH,TYPE,SIZE,RM,HOTPLUG,TRAN,VENDOR,MODEL,SERIAL,WWN,MOUNTPOINT,FSTYPE"


def _walk(nodes: list[dict[str, Any]], parent: str | None = None):
    for node in nodes:
        yield node, parent
        children = node.get("children") or []
        if children:
            yield from _walk(children, node.get("name"))


def parse_lsblk_json(data: dict[str, Any]) -> list[Observation]:
    observations: list[Observation] = []
    for node, parent in _walk(data.get("blockdevices", [])):
        name = node.get("name") or "?"
        serial = node.get("serial") or ""
        wwn = node.get("wwn") or ""
        identity = f"block:{name}"
        if serial:
            identity = f"block:{serial}"
        elif wwn:
            identity = f"block:{wwn}"
        model = (node.get("model") or "").strip()
        vendor = (node.get("vendor") or "").strip()
        node_type = node.get("type") or "?"
        label_bits = [b for b in (vendor, model) if b] or [name]
        label = f"{node_type} {' '.join(label_bits)} ({node.get('size') or '?'})"
        observations.append(
            Observation(
                kind=KIND_BLOCK_DEVICE,
                identity=identity,
                label=label,
                attributes={
                    "name": name,
                    "path": node.get("path"),
                    "type": node_type,
                    "size": node.get("size"),
                    "removable": bool(node.get("rm")),
                    "hotplug": bool(node.get("hotplug")),
                    "transport": node.get("tran"),
                    "vendor": vendor or None,
                    "model": model or None,
                    "serial": serial or None,
                    "wwn": wwn or None,
                    "fstype": node.get("fstype"),
                    "mountpoint": node.get("mountpoint"),
                    "parent": parent,
                },
            )
        )
    return observations


class BlockDeviceProbe(Probe):
    name = "block"
    description = "Inventory of block devices (disks/partitions), including transport"

    def availability(self) -> ProbeAvailability:
        if have_tool("lsblk"):
            return ProbeAvailability(ok=True)
        return ProbeAvailability(ok=False, detail="lsblk not found")

    def snapshot(self) -> list[Observation]:
        code, out, err = run_command(["lsblk", "-J", "-o", _COLUMNS])
        if code != 0 or not out.strip():
            # Older lsblk may not support all columns; retry with a minimal set.
            code, out, err = run_command(["lsblk", "-J"])
        if code != 0:
            raise RuntimeError(err.strip() or "lsblk failed")
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"could not parse lsblk JSON: {exc}") from exc
        return parse_lsblk_json(data)
