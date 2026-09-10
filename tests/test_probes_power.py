# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from cableprobe.config import Config
from cableprobe.models import KIND_POWER_READING
from cableprobe.probes import power as power_mod
from cableprobe.probes.power import PowerProbe, _swap16, _to_signed, read_ina219


class FakeBus:
    """Stand-in for smbus2.SMBus: returns canned little-endian words per register."""

    def __init__(self, shunt_word: int, bus_word: int):
        # SMBus word reads are little-endian; store the byte-swapped form so the
        # probe's own swap recovers the intended big-endian value.
        self._words = {0x01: _swap16(shunt_word), 0x02: _swap16(bus_word)}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read_word_data(self, address, register):
        return self._words[register]


def test_swap_and_sign_helpers():
    assert _swap16(0x1234) == 0x3412
    assert _to_signed(0x0064) == 100
    assert _to_signed(0xFFFF) == -1


def test_read_ina219_maths():
    # bus voltage register: value in bits 15..3, LSB 4 mV.  5.00 V -> 1250 -> <<3
    bus_word = 1250 << 3
    # shunt register LSB 10 uV.  With a 0.1 ohm shunt, 40 mA -> 4 mV -> 400 counts
    shunt_word = 400
    bus_v, current_ma = read_ina219(FakeBus(shunt_word, bus_word), 0x40, 0.1)
    assert round(bus_v, 2) == 5.0
    assert round(current_ma) == 40


def test_power_probe_snapshot_and_baseline(monkeypatch):
    readings = iter(
        [
            (5.02, 3.0),   # baseline
            (5.02, 3.0),
            (5.02, 3.0),
            (5.01, 3.0),   # (the extra voltage read)
            (5.00, 41.0),  # test - implant drawing ~38 mA more
            (5.00, 41.0),
            (5.00, 41.0),
            (5.00, 41.0),
        ]
    )
    monkeypatch.setattr(power_mod.PowerProbe, "_read", lambda self: next(readings))
    monkeypatch.setattr(power_mod, "SMBus", object())  # truthy so snapshot() runs

    probe = PowerProbe(Config(), 0.0)
    base = probe.snapshot()[0]
    assert base.kind == KIND_POWER_READING
    assert base.attributes["baseline_ma"] == base.attributes["current_ma"]
    assert base.attributes["excess_draw"] is False

    later = probe.snapshot()[0]
    assert later.attributes["delta_ma"] >= 30
    assert later.attributes["excess_draw"] is True
    assert later.attributes["voltage_ok"] is True


def test_power_probe_unavailable_without_smbus(monkeypatch):
    monkeypatch.setattr(power_mod, "SMBus", None)
    a = PowerProbe(Config(), 0.0).availability()
    assert a.ok is False and "smbus2" in a.detail
