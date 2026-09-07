# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""YAML-configurable detection rules.

A rule matches a :class:`~cableprobe.models.Delta` and, when it matches, emits a
:class:`~cableprobe.models.Finding`. The matching vocabulary is intentionally
small and declarative so operators can tune it without touching Python.
"""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from cableprobe.logging_config import get_logger
from cableprobe.models import Delta, Finding

log = get_logger("rules")

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_DEFAULT_RULES_RESOURCE = "default_rules.yaml"


class AttributeCondition(BaseModel):
    key: str
    equals: str | None = None
    not_equals: str | None = None
    exists: bool | None = None
    contains: str | None = None
    not_contains: str | None = None
    regex: str | None = None

    def evaluate(self, attributes: dict[str, Any]) -> bool:
        present = self.key in attributes and attributes[self.key] is not None
        value = attributes.get(self.key)
        svalue = "" if value is None else str(value)

        if self.exists is not None and present != self.exists:
            return False
        if self.equals is not None and svalue != self.equals:
            return False
        if self.not_equals is not None and svalue == self.not_equals:
            return False
        if self.contains is not None and self.contains.lower() not in svalue.lower():
            return False
        if self.not_contains is not None and self.not_contains.lower() in svalue.lower():
            return False
        if self.regex is not None and not re.search(self.regex, svalue, re.IGNORECASE):
            return False
        return True


class AttributeMatch(BaseModel):
    all: list[AttributeCondition] = Field(default_factory=list)
    any: list[AttributeCondition] = Field(default_factory=list)

    def evaluate(self, attributes: dict[str, Any]) -> bool:
        if self.all and not all(c.evaluate(attributes) for c in self.all):
            return False
        if self.any and not any(c.evaluate(attributes) for c in self.any):
            return False
        return True


def _as_list(value: str | list[str] | None) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    return list(value)


class RuleMatch(BaseModel):
    change: str | list[str] | None = None
    kind: str | list[str] | None = None
    first_seen_phase: str | list[str] | None = None
    reverted_after_disconnect: bool | None = None
    transient: bool | None = None
    label_regex: str | None = None
    attributes: AttributeMatch | None = None
    #: Require at least one related async event with one of these actions.
    event_action: str | list[str] | None = None

    def evaluate(self, delta: Delta) -> bool:
        change = _as_list(self.change)
        if change and delta.change not in change:
            return False
        kind = _as_list(self.kind)
        if kind and delta.kind not in kind:
            return False
        phases = _as_list(self.first_seen_phase)
        if phases and delta.first_seen_phase not in phases:
            return False
        if (
            self.reverted_after_disconnect is not None
            and delta.reverted_after_disconnect is not self.reverted_after_disconnect
        ):
            return False
        if self.transient is not None and delta.transient is not self.transient:
            return False
        if self.label_regex and not re.search(self.label_regex, delta.label, re.IGNORECASE):
            return False
        if self.attributes and not self.attributes.evaluate(delta.attributes):
            return False
        actions = _as_list(self.event_action)
        if actions and not any(e.action in actions for e in delta.related_events):
            return False
        return True


class Rule(BaseModel):
    id: str
    title: str
    severity: str = "medium"
    rationale: str = ""
    match: RuleMatch = Field(default_factory=RuleMatch)

    def check(self, delta: Delta) -> Finding | None:
        if not self.match.evaluate(delta):
            return None
        present_phases = ", ".join(p for p, v in delta.present_in.items() if v)
        evidence = [
            f"{delta.kind} '{delta.label}' ({delta.identity}) {delta.change}",
            f"present in: {present_phases}" if present_phases else "present in: (transient only)",
        ]
        if delta.reverted_after_disconnect is not None:
            evidence.append(
                "reverted after disconnect"
                if delta.reverted_after_disconnect
                else "did NOT revert after disconnect"
            )
        for change in delta.attribute_changes:
            evidence.append(f"attribute {change.key}: {change.before!r} -> {change.after!r}")
        for event in delta.related_events[:5]:
            evidence.append(
                f"udev {event.action} @ {event.timestamp.isoformat()} ({event.probe})"
            )
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            rationale=self.rationale,
            evidence=evidence,
            related_identities=[delta.identity],
        )


class RuleSet(BaseModel):
    version: int = 1
    rules: list[Rule] = Field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuleSet":
        return cls.model_validate(data)

    @classmethod
    def load(cls, path: Path | str) -> "RuleSet":
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"rules file not found: {path}")
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("rules file must contain a YAML mapping at the top level")
        return cls.from_dict(data)

    @classmethod
    def default(cls) -> "RuleSet":
        text = (
            resources.files("cableprobe.data")
            .joinpath(_DEFAULT_RULES_RESOURCE)
            .read_text(encoding="utf-8")
        )
        return cls.from_dict(yaml.safe_load(text) or {})

    @classmethod
    def resolve(cls, path: Path | str | None) -> "RuleSet":
        """Load from ``path`` if given, otherwise the packaged defaults."""

        if path is None:
            return cls.default()
        return cls.load(path)

    def evaluate(self, deltas: list[Delta]) -> list[Finding]:
        findings: list[Finding] = []
        for delta in deltas:
            for rule in self.rules:
                finding = rule.check(delta)
                if finding is not None:
                    findings.append(finding)
        findings.sort(
            key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True
        )
        return findings
