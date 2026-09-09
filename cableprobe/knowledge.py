# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Two operator-tunable lookup tables applied to the findings of a session:

* :class:`ImplantList` - USB vendor:product IDs shipped by off-the-shelf BadUSB
  / implant tools. A match raises a finding on its own.
* :class:`Allowlist` - devices the operator has told CableProbe to trust
  (``cableprobe allow``). Findings about an allowlisted device are downgraded to
  ``info`` so repeat tests of your own hardware stop shouting.

Both are just data; neither can prove anything. A blocklist match is a strong
lead (the tool may be reflashed with a spoofed ID); a non-match proves nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml

from cableprobe.logging_config import get_logger
from cableprobe.models import Delta, Finding

log = get_logger("knowledge")

_PACKAGED_IMPLANTS = "known_implants.yaml"
_ADD_ACTIONS = ("appeared", "modified")


def _hex_id(value: object) -> str:
    return str(value or "").strip().lower().removeprefix("0x").zfill(4)


# --------------------------------------------------------------------------
# known-implant blocklist
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ImplantEntry:
    vid: str
    pid: str
    name: str
    severity: str = "high"
    source: str = ""


class ImplantList:
    def __init__(self, entries: list[ImplantEntry]) -> None:
        self._by_id: dict[tuple[str, str], ImplantEntry] = {
            (e.vid, e.pid): e for e in entries
        }

    def __len__(self) -> int:
        return len(self._by_id)

    @classmethod
    def _parse(cls, data: dict) -> list[ImplantEntry]:
        out: list[ImplantEntry] = []
        for row in (data or {}).get("implants", []) or []:
            try:
                out.append(
                    ImplantEntry(
                        vid=_hex_id(row["vid"]),
                        pid=_hex_id(row["pid"]),
                        name=str(row.get("name") or "unknown"),
                        severity=str(row.get("severity") or "high"),
                        source=str(row.get("source") or ""),
                    )
                )
            except (KeyError, TypeError):
                log.warning("skipping malformed implant entry: %r", row)
        return out

    @classmethod
    def load(cls, extra: Path | str | None = None) -> "ImplantList":
        text = (
            resources.files("cableprobe.data")
            .joinpath(_PACKAGED_IMPLANTS)
            .read_text(encoding="utf-8")
        )
        entries = cls._parse(yaml.safe_load(text) or {})
        if extra is not None:
            path = Path(extra)
            if path.is_file():
                entries += cls._parse(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
            else:
                log.warning("implants_file not found: %s", path)
        return cls(entries)

    def match(self, vid: object, pid: object) -> ImplantEntry | None:
        return self._by_id.get((_hex_id(vid), _hex_id(pid)))

    def check(self, deltas: list[Delta]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for delta in deltas:
            if delta.change not in _ADD_ACTIONS:
                continue
            vid = delta.attributes.get("vendor_id")
            pid = delta.attributes.get("product_id")
            if not (vid and pid):
                continue
            entry = self.match(vid, pid)
            key = (_hex_id(vid), _hex_id(pid))
            if entry is None or key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id="known-implant-device",
                    title=(
                        f"USB {entry.vid}:{entry.pid} matches a known attack tool "
                        f"- {entry.name}"
                    ),
                    severity=entry.severity,
                    rationale=(
                        "This vendor:product ID is what this tool ships with in its "
                        "default configuration. Most of these tools can be reflashed "
                        "with a spoofed ID, so treat this as a strong lead rather "
                        "than proof - and check the behavioural findings."
                        + (f" Source: {entry.source}" if entry.source else "")
                    ),
                    evidence=[
                        f"{delta.kind} '{delta.label}' ({delta.identity})",
                        f"vendor:product = {entry.vid}:{entry.pid}",
                    ],
                    related_identities=[delta.identity],
                )
            )
        return findings


# --------------------------------------------------------------------------
# known-good allowlist
# --------------------------------------------------------------------------


@dataclass
class AllowEntry:
    vid: str
    pid: str
    serial: str | None
    name: str

    def as_dict(self) -> dict:
        row = {"vid": self.vid, "pid": self.pid, "name": self.name}
        if self.serial:
            row["serial"] = self.serial
        return row


class Allowlist:
    def __init__(self, entries: list[AllowEntry], path: Path | None = None) -> None:
        self.entries = entries
        self.path = path

    def __len__(self) -> int:
        return len(self.entries)

    @classmethod
    def load(cls, path: Path | str | None) -> "Allowlist":
        if path is None:
            return cls([], None)
        path = Path(path)
        if not path.is_file():
            return cls([], path)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        entries: list[AllowEntry] = []
        for row in data.get("allow", []) or []:
            try:
                entries.append(
                    AllowEntry(
                        vid=_hex_id(row["vid"]),
                        pid=_hex_id(row["pid"]),
                        serial=(str(row["serial"]) if row.get("serial") else None),
                        name=str(row.get("name") or "unnamed"),
                    )
                )
            except (KeyError, TypeError):
                log.warning("skipping malformed allowlist entry: %r", row)
        return cls(entries, path)

    def save(self) -> None:
        if self.path is None:
            raise ValueError("allowlist has no path to save to")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = yaml.safe_dump(
            {"allow": [e.as_dict() for e in self.entries]}, sort_keys=False
        )
        self.path.write_text(
            "# CableProbe allowlist - devices you trust; their findings are\n"
            "# downgraded to info. Prefer entries WITH a serial: an entry with no\n"
            "# serial trusts any device presenting that vendor:product.\n" + body,
            encoding="utf-8",
        )

    def match(self, vid: object, pid: object, serial: object) -> AllowEntry | None:
        v, p = _hex_id(vid), _hex_id(pid)
        s = str(serial) if serial else None
        for entry in self.entries:
            if entry.vid == v and entry.pid == p and (
                entry.serial is None or entry.serial == s
            ):
                return entry
        return None

    def add(self, vid: str, pid: str, serial: str | None, name: str) -> AllowEntry:
        entry = AllowEntry(_hex_id(vid), _hex_id(pid), serial or None, name)
        self.entries = [
            e
            for e in self.entries
            if not (e.vid == entry.vid and e.pid == entry.pid and e.serial == entry.serial)
        ]
        self.entries.append(entry)
        return entry


def apply_allowlist(
    findings: list[Finding], deltas: list[Delta], allowlist: Allowlist
) -> list[Finding]:
    """Return ``findings`` with any that concern an allowlisted device set to info."""

    if not allowlist.entries:
        return findings

    ids: dict[str, tuple[object, object, object]] = {
        d.identity: (
            d.attributes.get("vendor_id"),
            d.attributes.get("product_id"),
            d.attributes.get("serial"),
        )
        for d in deltas
    }

    out: list[Finding] = []
    for finding in findings:
        entry = None
        for identity in finding.related_identities:
            vid, pid, serial = ids.get(identity, (None, None, None))
            if vid and pid:
                entry = allowlist.match(vid, pid, serial)
                if entry is not None:
                    break
        if entry is None or finding.severity == "info":
            out.append(finding)
            continue
        out.append(
            finding.model_copy(
                update={
                    "severity": "info",
                    "title": f"{finding.title}  [allowlisted: {entry.name}]",
                    "rationale": (
                        f"Downgraded to info: you have allowlisted this device "
                        f"({entry.name}). " + finding.rationale
                    ),
                }
            )
        )
    return out
