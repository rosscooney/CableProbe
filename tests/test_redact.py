# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest

from cableprobe.redact import MASK, redact_cmdline

SECRET = "hunter2SuperSecretValue"


@pytest.mark.parametrize(
    "argv, must_not_contain, must_contain",
    [
        (["mysql", "--password", SECRET, "--host", "db"], SECRET, "--host db"),
        (["mysql", f"--password={SECRET}"], SECRET, "--password="),
        (["app", "--token", SECRET], SECRET, "--token"),
        (["curl", f"https://user:{SECRET}@example.com/x"], SECRET, "user:"),
        (["env", f"PGPASSWORD={SECRET}", "psql"], SECRET, "PGPASSWORD="),
        (["aws", f"AWS_SECRET_ACCESS_KEY={SECRET}"], SECRET, "AWS_SECRET_ACCESS_KEY="),
        (["svc", "--api-key", SECRET], SECRET, "--api-key"),
        (["j", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123ghi"],
         "eyJzdWIiOiIxMjM0", "j"),
        (["x", "AKIA" + "aB3" * 15], "aB3aB3aB3", "x"),  # long mixed-class blob
    ],
)
def test_redacts_common_secret_shapes(argv, must_not_contain, must_contain):
    out = redact_cmdline(argv)
    assert must_not_contain not in out
    assert MASK in out
    assert must_contain in out


@pytest.mark.parametrize(
    "argv",
    [
        ["/usr/bin/python3", "-m", "http.server", "8000"],
        ["rsync", "-av", "/home/pi/data/", "/mnt/backup/"],
        [" modemmanager".strip(), "--debug"],
        ["gpg", "--decrypt", "--output", "file.txt", "secret.txt.gpg"],
        ["git", "log", "--oneline", "0123456789abcdef0123456789abcdef01234567"],
    ],
)
def test_leaves_ordinary_command_lines_intact(argv):
    assert redact_cmdline(argv) == " ".join(argv)


def test_secret_flag_followed_by_another_flag_masks_nothing():
    out = redact_cmdline(["app", "--password", "--verbose", "--port", "22"])
    assert out == "app --password --verbose --port 22"


def test_accepts_a_string():
    assert redact_cmdline(f"login --secret {SECRET}") == f"login --secret {MASK}"
