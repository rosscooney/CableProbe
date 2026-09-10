# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import time

from cableprobe.config import Config
from cableprobe.models import KIND_POWER_READING, KIND_POWER_SERIES
from cableprobe.probes import power as power_mod
from cableprobe.probes.power import PowerProbe, _percentile, _swap16, _to_signed, read_ina219


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


def test_percentile_nearest_rank():
    assert _percentile([10], 95) == 10
    assert _percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50) == 5
    assert _percentile([1] * 95 + [100] * 5, 95) == 1
    assert _percentile([1] * 90 + [100] * 10, 95) == 100


def test_power_probe_emits_waveform_series(monkeypatch):
    steady = (5.0, 4.0)
    spike = (5.0, 120.0)
    # snapshot() reads 4x; between snapshots the sampler reads via _sample_once()
    stream = iter(
        [steady] * 4                       # baseline snapshot -> baseline_ma
        + [steady] * 30 + [spike] * 2       # 32 samples, 2 well over threshold
        + [steady] * 4                      # end snapshot
        + [steady] * 100                    # slack
    )
    monkeypatch.setattr(power_mod.PowerProbe, "_read", lambda self: next(stream))
    monkeypatch.setattr(power_mod, "SMBus", object())

    probe = PowerProbe(Config(), 0.0)
    assert probe.snapshot()[0].attributes["baseline_ma"] == 4  # bucketed 4.0

    for _ in range(32):
        probe._sample_once()

    series = next(o for o in probe.snapshot() if o.kind == KIND_POWER_SERIES)
    a = series.attributes
    assert a["sample_count"] == 32
    assert a["max_current_ma"] == 120
    assert a["spike_count"] == 2
    assert a["current_spike"] is True
    assert a["sustained_excess"] is False  # 2/32 samples, p95 still at baseline
    # a second snapshot with nothing sampled in between emits no series
    assert all(o.kind != KIND_POWER_SERIES for o in probe.snapshot())


def test_power_sampler_thread_starts_and_stops(monkeypatch):
    monkeypatch.setattr(power_mod.PowerProbe, "_read", lambda self: (5.0, 5.0))
    monkeypatch.setattr(power_mod, "SMBus", object())
    import asyncio

    probe = PowerProbe(Config(), 0.0)
    probe._sample_interval = 0.01
    asyncio.run(probe.start())
    time.sleep(0.1)
    asyncio.run(probe.stop())
    assert probe._sampler is None
    assert len(probe._drain_window()) > 0  # the thread sampled while alive


def test_power_probe_unavailable_without_smbus(monkeypatch):
    monkeypatch.setattr(power_mod, "SMBus", None)
    a = PowerProbe(Config(), 0.0).availability()
    assert a.ok is False and "smbus2" in a.detail


def test_power_probe_unavailable_when_bus_read_errors(monkeypatch, tmp_path):
    monkeypatch.setattr(power_mod, "SMBus", object)  # not None
    monkeypatch.setattr(power_mod.Path, "exists", lambda self: True)

    def _boom(self):
        raise OSError(121, "Remote I/O error")

    monkeypatch.setattr(power_mod.PowerProbe, "_read", _boom)
    a = PowerProbe(Config(), 0.0).availability()
    assert a.ok is False and "no INA219 responding" in a.detail
