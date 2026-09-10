# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Block device inventory via ``lsblk -J``.

A cable that causes a new mass-storage device to enumerate is a strong signal,
so transport (``tran``) and hotplug status are recorded.
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


def _partition_summary(node: dict[str, Any]) -> list[dict[str, str | None]]:
    parts: list[dict[str, str | None]] = []
    for child, _ in _walk(node.get("children") or []):
        if (child.get("type") or "") == "part":
            parts.append(
                {
                    "name": child.get("name"),
                    "size": child.get("size"),
                    "fstype": child.get("fstype"),
                    "mountpoint": child.get("mountpoint"),
                }
            )
    return parts


def parse_lsblk_json(data: dict[str, Any]) -> list[Observation]:
    observations: list[Observation] = []
    for node, parent in _walk(data.get("blockdevices", [])):
        node_type = node.get("type") or "?"
        # Partitions are part of their disk, not independently interesting - they
        # are summarised onto the parent below. (LVM / crypt / md nodes are kept.)
        if node_type == "part":
            continue
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
        label_bits = [b for b in (vendor, model) if b] or [name]
        label = f"{node_type} {' '.join(label_bits)} ({node.get('size') or '?'})"
        partitions = _partition_summary(node)
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
                    "partitions": [p["name"] for p in partitions] or None,
                    "partition_count": len(partitions) or None,
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
