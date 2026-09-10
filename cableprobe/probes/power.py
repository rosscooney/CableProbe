# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Inline USB VBUS voltage / current via an INA219 on the Pi's I2C bus.

This is the one measurement a cable cannot lie about. A passive cable, and a
simple passive adapter, draw a negligible and stable amount of current. Powered
electronics inside the cable or connector - a microcontroller, a Wi-Fi / BLE
radio - draw tens of milliamps, and that shows up here regardless of what the
USB descriptors claim.

Wiring: an INA219 breakout in series with the USB VBUS line going to the port
under test (VIN+ from the host 5 V, VIN- to the connector), SDA/SCL/GND to the
Pi. Default I2C address 0x40, default 0.1 ohm shunt.

Not a default probe: it needs the hardware, plus ``pip install cableprobe[power]``
for ``smbus2``. Enable it in ``probes.enabled`` once wired.

For a clean reading, run the TEST phase with the cable connected but **nothing**
on its far end - then any current above a few mA is electronics in the cable.
If you connect a real device, some draw is expected; compare it to that
device's rated current.
"""

from __future__ import annotations

from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_POWER_READING, Observation
from cableprobe.probes.base import Probe, ProbeAvailability

try:  # optional dependency
    from smbus2 import SMBus
except ImportError:
    SMBus = None  # type: ignore[assignment,misc]

log = get_logger("probe.power")

_REG_SHUNT_VOLTAGE = 0x01
_REG_BUS_VOLTAGE = 0x02

#: A plausible VBUS window. USB 2.0 spec is 4.75-5.25 V at the host; real hubs
#: and cables sag / ring a bit wider than that.
_VBUS_MIN = 4.40
_VBUS_MAX = 5.60

#: mA bucket - suppresses ADC noise so a steady draw does not churn "modified"
#: deltas every sample.
_CURRENT_BUCKET_MA = 2


def _swap16(word: int) -> int:
    """SMBus word reads are little-endian; the INA219 is big-endian."""

    return ((word << 8) | (word >> 8)) & 0xFFFF


def _to_signed(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def read_ina219(bus, address: int, shunt_ohms: float) -> tuple[float, float]:
    """Return ``(bus_voltage_v, current_ma)`` from an INA219 at ``address``."""

    shunt_raw = _to_signed(_swap16(bus.read_word_data(address, _REG_SHUNT_VOLTAGE)))
    bus_raw = _swap16(bus.read_word_data(address, _REG_BUS_VOLTAGE))
    shunt_v = shunt_raw * 1e-5  # LSB = 10 uV
    bus_v = (bus_raw >> 3) * 4e-3  # LSB = 4 mV, bits 15..3
    current_ma = (shunt_v / shunt_ohms) * 1000.0 if shunt_ohms else 0.0
    return bus_v, current_ma


class PowerProbe(Probe):
    name = "power"
    description = "Inline USB VBUS voltage / current (INA219 over I2C) - unspoofable"

    def __init__(self, config, session_start: float) -> None:
        super().__init__(config, session_start)
        self._bus_no = int(config.probes.power_i2c_bus)
        self._address = int(config.probes.power_i2c_address)
        self._shunt = float(config.probes.power_shunt_ohms)
        self._alert_ma = int(config.probes.power_alert_ma)
        self._baseline_ma: float | None = None

    # -- helpers --------------------------------------------------------

    def _read(self) -> tuple[float, float]:
        with SMBus(self._bus_no) as bus:
            return read_ina219(bus, self._address, self._shunt)

    # -- lifecycle ---------------------------------------------------

    def availability(self) -> ProbeAvailability:
        if SMBus is None:
            return ProbeAvailability(
                ok=False, detail="smbus2 not installed (pip install 'cableprobe[power]')"
            )
        dev = Path(f"/dev/i2c-{self._bus_no}")
        if not dev.exists():
            return ProbeAvailability(
                ok=False, detail=f"{dev} not present (enable I2C: raspi-config / dtparam=i2c_arm=on)"
            )
        try:
            self._read()
        except OSError as exc:  # bus present but nothing ACKs at this address
            return ProbeAvailability(
                ok=False,
                detail=f"no INA219 responding at 0x{self._address:02x} on i2c-{self._bus_no} ({exc})",
            )
        return ProbeAvailability(
            ok=True, detail=f"INA219 at 0x{self._address:02x} on i2c-{self._bus_no}"
        )

    def snapshot(self) -> list[Observation]:
        if SMBus is None:
            raise RuntimeError("smbus2 not available")
        # A couple of quick reads and take the median-ish middle value.
        samples = sorted(self._read()[1] for _ in range(3))
        current_ma = samples[1]
        bus_v, _ = self._read()

        current_ma = round(current_ma / _CURRENT_BUCKET_MA) * _CURRENT_BUCKET_MA
        if self._baseline_ma is None:
            self._baseline_ma = current_ma
        delta_ma = current_ma - self._baseline_ma
        excess = delta_ma > self._alert_ma
        voltage_ok = _VBUS_MIN <= bus_v <= _VBUS_MAX

        sign = "+" if delta_ma >= 0 else ""
        return [
            Observation(
                kind=KIND_POWER_READING,
                identity="power:vbus",
                label=(
                    f"USB VBUS {bus_v:.2f} V, {current_ma:.0f} mA "
                    f"({sign}{delta_ma:.0f} mA vs no-cable baseline)"
                ),
                attributes={
                    "bus_voltage_v": round(bus_v, 2),
                    "current_ma": current_ma,
                    "baseline_ma": self._baseline_ma,
                    "delta_ma": delta_ma,
                    "excess_draw": excess,
                    "voltage_ok": voltage_ok,
                    "alert_threshold_ma": self._alert_ma,
                },
            )
        ]
