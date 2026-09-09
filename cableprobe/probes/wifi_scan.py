# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Wi-Fi access-point scan.

Several cable implants (O.MG and similar) carry their own radio and bring up a
Wi-Fi access point for out-of-band control. That AP cannot be seen on the USB
side at all, but if the test host has a Wi-Fi interface it *can* be seen over
the air: an AP that was not in range during the baseline and appears -- with a
strong signal -- while the cable is connected is a serious finding.

This probe runs an active scan (``iw dev <iface> scan``, or ``nmcli dev wifi
list`` as a fallback) once per phase boundary. An active scan briefly disrupts
the Wi-Fi association, so it is deliberately **not** run on every sample tick,
and on a host with no Wi-Fi interface the probe simply reports itself
unavailable.

Only AP metadata (BSSID, SSID, signal, channel) is recorded -- no traffic is
captured and the host never associates with a discovered AP.
"""

from __future__ import annotations

import re
from pathlib import Path

from cableprobe.logging_config import get_logger
from cableprobe.models import KIND_WIFI_AP, Observation
from cableprobe.probes.base import Probe, ProbeAvailability, have_tool, run_command

log = get_logger("probe.wifi_scan")

SYS_CLASS_NET = "/sys/class/net"

#: At or above this RSSI an AP is close enough to plausibly be in the cable /
#: connector rather than a neighbour's network.
STRONG_SIGNAL_DBM = -55.0


def wifi_interfaces(root: str = SYS_CLASS_NET) -> list[str]:
    """Return the names of Wi-Fi interfaces (those with an ``802.11`` phy)."""

    base = Path(root)
    if not base.is_dir():
        return []
    out: list[str] = []
    for entry in sorted(base.iterdir()):
        if (entry / "phy80211").exists() or (entry / "wireless").exists():
            out.append(entry.name)
    return out


# --------------------------------------------------------------------------
# iw
# --------------------------------------------------------------------------

_IW_BSS = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})\(on \S+\)(?P<assoc>.*)$")
_IW_SIGNAL = re.compile(r"^\s*signal:\s*(-?\d+(?:\.\d+)?)\s*dBm")
_IW_FREQ = re.compile(r"^\s*freq:\s*(\d+)")
_IW_SSID = re.compile(r"^\s*SSID:\s*(.*)$")


def _channel_for_freq(mhz: int | None) -> int | None:
    if mhz is None:
        return None
    if 2412 <= mhz <= 2472:
        return (mhz - 2412) // 5 + 1
    if mhz == 2484:
        return 14
    if 5160 <= mhz <= 5885:
        return (mhz - 5000) // 5
    return None


def parse_iw_scan(text: str, *, interface: str = "wlan0") -> list[Observation]:
    """Parse ``iw dev <iface> scan`` output into wifi_ap observations."""

    aps: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        bss = _IW_BSS.match(line)
        if bss:
            if current:
                aps.append(current)
            current = {
                "bssid": bss.group(1).lower(),
                "associated": "associated" in bss.group("assoc"),
                "signal_dbm": None,
                "freq": None,
                "ssid": None,
            }
            continue
        if current is None:
            continue
        m = _IW_SIGNAL.match(line)
        if m:
            current["signal_dbm"] = float(m.group(1))
            continue
        m = _IW_FREQ.match(line)
        if m:
            current["freq"] = int(m.group(1))
            continue
        m = _IW_SSID.match(line)
        if m:
            current["ssid"] = m.group(1).strip() or "<hidden>"
    if current:
        aps.append(current)
    return [_ap_observation(ap, interface) for ap in aps]


# --------------------------------------------------------------------------
# nmcli
# --------------------------------------------------------------------------


def parse_nmcli_wifi(text: str, *, interface: str = "wlan0") -> list[Observation]:
    """Parse ``nmcli -t -f BSSID,SSID,CHAN,FREQ,SIGNAL,IN-USE dev wifi`` output."""

    observations: list[Observation] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        # nmcli terse mode escapes ':' inside fields as '\:'.
        fields = re.split(r"(?<!\\):", line)
        fields = [f.replace("\\:", ":") for f in fields]
        if len(fields) < 6:
            continue
        bssid, ssid, chan, freq, signal, in_use = fields[:6]
        freq_mhz = None
        fm = re.search(r"\d+", freq)
        if fm:
            freq_mhz = int(fm.group(0))
        ap = {
            "bssid": bssid.lower(),
            "ssid": ssid or "<hidden>",
            "signal_dbm": _nmcli_signal_to_dbm(signal),
            "freq": freq_mhz,
            "channel": int(chan) if chan.isdigit() else None,
            "associated": in_use.strip() in ("*", "yes"),
        }
        observations.append(_ap_observation(ap, interface))
    return observations


def _nmcli_signal_to_dbm(value: str) -> float | None:
    """nmcli reports SIGNAL as 0-100 quality; map back to an approximate dBm."""

    if not value.strip().isdigit():
        return None
    quality = int(value)
    # Linux wext convention: dBm = quality/2 - 100.
    return round(quality / 2 - 100, 1)


# --------------------------------------------------------------------------
# shared
# --------------------------------------------------------------------------


def oui_family(bssid: str) -> str:
    """A coarse "same physical AP" key for a BSSID.

    Enterprise / mesh APs (UniFi, Aruba, ...) broadcast many BSSIDs per physical
    unit - one per band, per SSID, per virtual AP - and a scan sees a rotating
    subset each time, so BSSID-level tracking is hopeless. The vendor OUI with
    the multicast + locally-administered bits of the first octet cleared groups
    ``bc:30:d9:85:…`` and ``be:30:d9:a5:…`` (the same UniFi AP) together.
    """

    parts = bssid.lower().split(":")
    if len(parts) != 6:
        return bssid.lower()
    try:
        first = int(parts[0], 16) & 0xFC
    except ValueError:
        return bssid.lower()
    return f"{first:02x}:{parts[1]}:{parts[2]}"


def _ap_observation(ap: dict, interface: str) -> Observation:
    signal = ap.get("signal_dbm")
    channel = ap.get("channel") or _channel_for_freq(ap.get("freq"))
    strong = signal is not None and signal >= STRONG_SIGNAL_DBM
    ssid = ap.get("ssid") or "<hidden>"
    return Observation(
        kind=KIND_WIFI_AP,
        identity=f"wifi:{ap['bssid']}",
        label=f"Wi-Fi AP {ssid} ({ap['bssid']})"
        + (f" {signal:.0f} dBm" if signal is not None else ""),
        attributes={
            "bssid": ap["bssid"],
            "ssid": ssid,
            "signal_dbm": signal,
            "freq": ap.get("freq"),
            "channel": channel,
            "strong_signal": strong,
            "associated": bool(ap.get("associated")),
            "scanned_via": interface,
        },
    )


class WifiScanProbe(Probe):
    name = "wifi_scan"
    description = "Wi-Fi access points in range (a cable implant may run its own AP)"
    # An active scan disrupts the Wi-Fi association; only run it at phase edges.
    samples_periodically = False

    def __init__(self, config, session_start: float) -> None:
        super().__init__(config, session_start)
        #: OUI-families (see ``oui_family``) seen in any earlier scan this
        #: session. An AP whose family is already here is an existing network on
        #: the premises, not something the cable brought.
        self._seen_families: set[str] = set()

    def _tool(self) -> str | None:
        if have_tool("iw"):
            return "iw"
        if have_tool("nmcli"):
            return "nmcli"
        return None

    def availability(self) -> ProbeAvailability:
        tool = self._tool()
        if tool is None:
            return ProbeAvailability(ok=False, detail="neither iw nor nmcli present")
        interfaces = wifi_interfaces(SYS_CLASS_NET)
        if not interfaces:
            return ProbeAvailability(ok=False, detail="no Wi-Fi interface")
        return ProbeAvailability(
            ok=True, detail=f"using {tool} on {', '.join(interfaces)}"
        )

    def snapshot(self) -> list[Observation]:
        tool = self._tool()
        if tool is None:
            raise RuntimeError("no Wi-Fi scan tool (iw / nmcli)")
        observations: list[Observation] = []
        seen: set[str] = set()
        for iface in wifi_interfaces():
            if tool == "iw":
                code, out, err = run_command(
                    ["iw", "dev", iface, "scan"], timeout=20.0
                )
                if code != 0:
                    log.info("iw scan on %s failed: %s", iface, err.strip())
                    continue
                found = parse_iw_scan(out, interface=iface)
            else:
                code, out, err = run_command(
                    [
                        "nmcli",
                        "-t",
                        "-f",
                        "BSSID,SSID,CHAN,FREQ,SIGNAL,IN-USE",
                        "dev",
                        "wifi",
                        "list",
                        "--rescan",
                        "yes",
                    ],
                    timeout=20.0,
                )
                if code != 0:
                    log.info("nmcli wifi list on %s failed: %s", iface, err.strip())
                    continue
                found = parse_nmcli_wifi(out, interface=iface)
            for obs in found:
                if obs.identity in seen:
                    continue
                seen.add(obs.identity)
                observations.append(obs)

        # Mark APs whose OUI-family was not present in any earlier scan. Done
        # against a frozen copy so every BSSID of a genuinely new AP is flagged.
        prior = frozenset(self._seen_families)
        for obs in observations:
            family = oui_family(obs.attributes.get("bssid", ""))
            obs.attributes["family_new_this_session"] = family not in prior
            self._seen_families.add(family)
        return observations
