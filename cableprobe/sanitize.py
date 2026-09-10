# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Sanitisation for untrusted, device-supplied text.

CableProbe's whole job is to inspect hostile hardware, and a lot of the strings
it handles (USB string descriptors, device names, kernel log lines) are fully
attacker-controlled. Those strings end up in the JSON report and on the
operator's terminal, so before they are stored or displayed we:

* replace C0/C1 control characters and DEL with U+FFFD (defeats raw ANSI escape
  injection into the operator's terminal),
* collapse newlines / carriage returns to spaces,
* bound the length (defeats descriptor-based memory amplification).
"""

from __future__ import annotations

import re
from typing import Any

# C0 controls except tab, plus DEL and the C1 range.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

DEFAULT_MAX_LEN = 512
IDENTITY_MAX_LEN = 256


def clean_text(value: Any, *, max_len: int = DEFAULT_MAX_LEN) -> Any:
    """Return ``value`` with control characters removed and length bounded.

    Non-string values are returned unchanged. ``None`` stays ``None``.
    """

    if not isinstance(value, str):
        return value
    text = _CONTROL_CHARS.sub("�", value)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = text.strip()
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def clean_scalar(value: Any, *, max_len: int = DEFAULT_MAX_LEN) -> Any:
    """Sanitise a scalar or a (possibly nested) list/tuple of scalars."""

    if isinstance(value, (list, tuple)):
        return [clean_scalar(item, max_len=max_len) for item in value]
    return clean_text(value, max_len=max_len)


def clean_deep(value: Any, *, max_len: int = DEFAULT_MAX_LEN) -> Any:
    """Recursively sanitise every string in nested dicts / lists / tuples -
    for a free-form structure loaded from an untrusted report (the summary)."""

    if isinstance(value, dict):
        return {
            clean_text(k, max_len=128): clean_deep(v, max_len=max_len)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [clean_deep(v, max_len=max_len) for v in value]
    return clean_text(value, max_len=max_len)


def clean_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """Sanitise every string value in an attributes mapping (keys included)."""

    return {
        clean_text(key, max_len=128): clean_scalar(val)
        for key, val in attributes.items()
    }
