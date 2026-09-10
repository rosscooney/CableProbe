# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Mask obvious secrets in captured process command lines.

``probes.capture_process_cmdline`` records the argv of processes that started
during a session. That is useful ("a helper daemon spawned with these flags")
but argv routinely carries passwords, tokens and API keys, and reports get
pasted into issues. This is a best-effort scrubber: it catches the common
shapes (``--password x`` including a value that starts with ``-``, ``TOKEN=x``,
``curl -u user:pass`` and the glued ``-uuser:pass``, ``user:pass@host`` URLs,
JWTs, long high-entropy blobs)
and is deliberately conservative elsewhere so ordinary command lines stay
readable. It is not a guarantee - a bespoke secret flag or a secret in a bare
positional argument still slips through, which is why the report flags a
session whenever a value was masked.
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

#: Flags whose value is ``user:password`` (curl / wget / git-style). The
#: username is kept, everything after the first ``:`` is masked.
_USERPASS_FLAGS = {"-u", "--user", "-U", "--proxy-user"}

#: ``user:password`` -> ``user:***`` (only when we know the arg is a credential).
_USERPASS = re.compile(r"^([^:\s]+):.+$", re.DOTALL)

#: A short userpass option with its value glued on: ``-ualice:secret``. Only
#: matched when the value looks like ``user:pass`` (a bare ``-u1000`` is left
#: alone).
_GLUED_USERPASS = re.compile(r"^(-[uU])([^\s:]+:.+)$", re.DOTALL)


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


def _mask_userpass(value: str) -> str:
    return _USERPASS.sub(rf"\1:{MASK}", value)


def redact_arg(token: str) -> str:
    """Redact a single argv token in isolation (no look-ahead)."""

    m = _GLUED_USERPASS.match(token)
    if m:
        return m.group(1) + _mask_userpass(m.group(2))

    if "://" in token and _URL_CRED.search(token):
        token = _URL_CRED.sub(rf"\1{MASK}\2", token)

    if _JWT.search(token):
        token = _JWT.sub(MASK, token)

    m = _KV.match(token)
    if m:
        key = m.group("key")
        if key.lstrip("-") in {f.lstrip("-") for f in _USERPASS_FLAGS} and m.group(
            "sep"
        ) == "=":
            return f"{key}={_mask_userpass(m.group('val'))}"
        if _SECRET_WORD.search(key):
            return f"{key}{m.group('sep')}{MASK}"

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
    userpass_next = False
    for arg in args:
        if mask_next:
            # the value of a credential flag - mask it even if it starts with a
            # dash (a password can; over-masking a stray flag is the safe error)
            mask_next = False
            out.append(MASK)
            continue
        if userpass_next:
            userpass_next = False
            out.append(_mask_userpass(arg))
            continue
        out.append(redact_arg(arg))
        if arg in _USERPASS_FLAGS:
            userpass_next = True
        elif _is_secret_flag(arg):
            mask_next = True
    # a trailing "--password" with no following value is left as-is
    return " ".join(out)
