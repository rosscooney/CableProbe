# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from cableprobe.models import Observation, ProbeEvent, utcnow
from cableprobe.sanitize import clean_attributes, clean_scalar, clean_text


def test_clean_text_neutralises_control_and_ansi():
    # control bytes (incl. ESC) are replaced with U+FFFD, never passed through
    assert clean_text("evil\x1b[31mred\x1b[0m") == "evil�[31mred�[0m"
    assert "\x1b" not in clean_text("\x1b]0;title\x07")
    assert clean_text("a\x00b\x07c") == "a�b�c"


def test_clean_text_collapses_newlines_and_trims():
    assert clean_text("  line1\r\nline2\t end  ") == "line1  line2  end"


def test_clean_text_bounds_length():
    out = clean_text("x" * 5000, max_len=10)
    assert len(out) == 10
    assert out.endswith("…")


def test_clean_text_passes_through_non_strings():
    assert clean_text(5) == 5
    assert clean_text(None) is None
    assert clean_text(True) is True


def test_clean_scalar_handles_lists():
    assert clean_scalar(["a\x00", "b", 3]) == ["a�", "b", 3]


def test_clean_attributes_sanitises_keys_and_values():
    out = clean_attributes({"na\x00me": "val\x1bue", "count": 2, "tags": ["x\x07"]})
    assert "na�me" in out
    assert out["na�me"] == "val�ue"
    assert out["count"] == 2
    assert out["tags"] == ["x�"]


def test_observation_sanitises_on_construction():
    obs = Observation(
        kind="usb_device",
        identity="usb:1\x00:2",
        label="Cable\x1b[2J",
        attributes={"product": "P\x07wn", "vid": "1d6b"},
    )
    assert "\x00" not in obs.identity
    assert "\x1b" not in obs.label
    assert obs.attributes["product"] == "P�wn"
    assert obs.attributes["vid"] == "1d6b"


def test_probe_event_sanitises_on_construction():
    ev = ProbeEvent(
        timestamp=utcnow(),
        probe="udev_monitor",
        action="add\x00",
        kind="input_device",
        identity="input:evil",
        label="KB\x1b[31m",
        attributes={"NAME": "x\x07"},
    )
    assert ev.action == "add�"  # control byte neutralised, not passed through
    assert "\x1b" not in ev.label
    assert ev.attributes["NAME"] == "x�"
