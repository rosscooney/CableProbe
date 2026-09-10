# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Mask obvious secrets in captured process command lines.

``probes.capture_process_cmdline`` records the argv of processes that started
during a session. That is useful ("a helper daemon spawned with these flags")
but argv routinely carries passwords, tokens and API keys, and reports get
pasted into issues. This is a best-effort scrubber: it catches the common
shapes (``--password x``, ``TOKEN=x``, ``user:pass@host`` URLs, JWTs, long
high-entropy blobs) and is deliberately conservative elsewhere so ordinary
command lines stay readable. It is not a guarantee — the report warning still
tells the operator to review before sharing.
"""

from __future__ import annotations

import re

MASK = "***"

#: Substring that marks a flag or key name as carrying a credential.
_SECRET_WORD = re.compile(
    r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|access[-_]?key|"
    r"auth|bearer|credential|client[-_]?secret|private[-_]?key|"
    r"session[-_]?(?:key|token)|otp|passcode)"
)

#: ``scheme://user:password@host`` -> keep the user, drop the password.
_URL_CRED = re.compile(
    r"([a-z][a-z0-9+.\-]*://[^\s:/@]+:)[^\s/@]+(@)", re.IGNORECASE
)

#: A JSON Web Token (``eyJ...header.payload.signature``).
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")

#: Splits ``KEY=VALUE`` / ``KEY:VALUE`` (first separator only).
_KV = re.compile(r"^(?P<key>[^\s=:]+)(?P<sep>[=:])(?P<val>.+)$", re.DOTALL)


def _looks_high_entropy(token: str) -> bool:
    """True for a long mixed-class blob that is almost certainly a key/token
    and almost certainly not a path, hostname or ordinary word."""

    if len(token) < 40 or "/" in token or "\\" in token or "." in token:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+_=-]+", token):
        return False
    return (
        any(c.islower() for c in token)
        and any(c.isupper() for c in token)
        and any(c.isdigit() for c in token)
    )


def _is_secret_flag(token: str) -> bool:
    return (
        token.startswith("-")
        and "=" not in token
        and ":" not in token
        and bool(_SECRET_WORD.search(token))
    )


def redact_arg(token: str) -> str:
    """Redact a single argv token in isolation (no look-ahead)."""

    if "://" in token and _URL_CRED.search(token):
        token = _URL_CRED.sub(rf"\1{MASK}\2", token)

    if _JWT.search(token):
        token = _JWT.sub(MASK, token)

    m = _KV.match(token)
    if m and _SECRET_WORD.search(m.group("key")):
        return f"{m.group('key')}{m.group('sep')}{MASK}"

    if _looks_high_entropy(token):
        return MASK

    return token


def redact_cmdline(cmdline: list[str] | tuple[str, ...] | str) -> str:
    """Return the command line as a single string with obvious secrets masked."""

    if isinstance(cmdline, str):
        args = cmdline.split()
    else:
        args = [str(a) for a in cmdline]

    out: list[str] = []
    mask_next = False
    for arg in args:
        if mask_next:
            mask_next = False
            if not arg.startswith("-"):  # the flag's value; a new flag is not
                out.append(MASK)
                continue
        out.append(redact_arg(arg))
        if _is_secret_flag(arg):
            mask_next = True
    # a trailing "--password" with no following value is left as-is
    return " ".join(out)
