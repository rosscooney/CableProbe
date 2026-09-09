# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Plain-language interpretation of a session for the operator.

The delta table and findings are precise but assume you know what a "CDC ethernet
gadget" or an "HID interface" is. :func:`build_advice` turns a
:class:`~cableprobe.models.SessionReport` into a short "what this means / what to
do" box aimed at a moderately technical reader.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cableprobe.models import SessionReport

# --------------------------------------------------------------------------
# themes: map a finding (by rule id, falling back to kind) to one plain-English
# explanation. Order here is the order they are shown in.
# --------------------------------------------------------------------------

_THEMES: list[tuple[str, tuple[str, ...], str]] = [
    (
        "dma",
        ("pci-device-appeared", "thunderbolt"),
        "The cable brought up a PCI / Thunderbolt device. That can let hardware "
        "read and write your computer's memory directly — one of the most "
        "serious things a cable can do. Disconnect it and do not reconnect it.",
    ),
    (
        "keystroke-injection",
        ("keystroke-injection", "keystrokes-during-test"),
        "CableProbe measured typing that is too fast or too regular to be human. "
        "Something was actively typing into this computer while the cable was "
        "connected — the classic behaviour of a keystroke-injection implant.",
    ),
    (
        "badusb",
        ("hid-keyboard", "hid-pointer", "hid-interface", "hid-generic", "composite-with-hid"),
        "A keyboard / mouse-type device appeared when you connected the cable. "
        "This is the most common trick for a malicious cable: a hidden keyboard "
        "that types commands by itself ('BadUSB'), or a hidden mouse that clicks "
        "through confirmation prompts. If you did not deliberately connect an "
        "input device through this cable, treat it as an attack tool.",
    ),
    (
        "network",
        ("network-interface", "default-route-changed", "dns-resolvers-changed", "ethernet-gadget"),
        "The cable made the computer think a network adapter was plugged in. A "
        "cable that does this can sit between you and the internet and read, "
        "redirect or fake the sites and services you connect to"
        " — and here it changed where traffic actually goes.",
    ),
    (
        "storage",
        ("mass-storage", "storage-interface", "removable-media-mounted", "mount-persisted"),
        "The cable presented a USB drive to the computer. That storage could "
        "carry malware, auto-run content, or be used to copy files off the "
        "machine.",
    ),
    (
        "serial",
        ("serial-device",),
        "A serial / 'modem' device appeared. These are often used as a hidden "
        "two-way channel to send commands to, or pull data from, the computer.",
    ),
    (
        "capture",
        ("audio-video", "audio-device", "video-device"),
        "The cable added a microphone or camera. That is a way to listen to or "
        "watch the room through something that looks like a plain cable.",
    ),
    (
        "radio",
        ("strong-wifi-ap",),
        "A strong Wi-Fi network appeared when you connected the cable and "
        "disappeared when you unplugged it. Some attack cables carry their own "
        "Wi-Fi so an attacker can control them from across the room or building "
        "- this is what that looks like.",
    ),
    (
        "power-delivery",
        ("typec-data-role", "typec-alt-mode"),
        "The cable negotiated abilities — a data role, or a DisplayPort / "
        "Thunderbolt mode — that a plain charging cable has no reason to ask "
        "for.",
    ),
    (
        "driver",
        ("gadget-driver-module",),
        "The system loaded a network, serial or Bluetooth driver when the cable "
        "went in - a plain charge/data cable never makes that happen.",
    ),
    (
        "hub",
        ("usb-hub-appeared",),
        "A USB hub appeared inside the connection. Hidden hubs are how several "
        "malicious devices (keyboard + storage + network) are stacked behind a "
        "single plug.",
    ),
    (
        "listener",
        ("new-listener",),
        "A program started listening for network connections while the cable was "
        "in. It may be unrelated, but it is worth checking what it was.",
    ),
    (
        "process",
        ("new-process-after-connect",),
        "New software started running around the time you connected the cable. "
        "Often this is just the system reacting to a new device; sometimes it "
        "is not.",
    ),
]

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Advice:
    """A short plain-language read of the session."""

    headline: str
    severity: str  # highest finding severity, or "none"
    body: list[str] = field(default_factory=list)


def _themes_present(report: SessionReport) -> list[str]:
    rule_ids = {f.rule_id for f in report.findings}
    out: list[str] = []
    for key, needles, sentence in _THEMES:
        if any(n in rid for rid in rule_ids for n in needles):
            out.append(sentence)
    return out


def build_advice(report: SessionReport) -> Advice:
    severity = report.summary.get("highest_severity") or "none"
    persisted = int(report.summary.get("persisted_after_disconnect_count") or 0)
    cable_changes = int(report.summary.get("cable_correlated_change_count") or 0)

    if severity == "critical":
        headline = "Treat this cable as hostile hardware."
        verdict = [
            "CableProbe saw behaviour that a normal cable never shows. Unplug it "
            "now, keep it away from anything you care about, and if this ran on a "
            "machine that matters, assume that machine is compromised.",
        ]
    elif severity == "high":
        headline = "This cable did something a plain charge/data cable should not do."
        verdict = [
            "Unless you know exactly why (for example, you deliberately connected "
            "a keyboard through it), do not trust or reuse this cable. Keep it "
            "away from any computer that holds real data.",
        ]
    elif severity == "medium":
        headline = "Something changed when the cable was connected — take a closer look."
        verdict = [
            "Run the test again to see whether it repeats, check the findings "
            "below against what you actually plugged in, and don't rely on this "
            "cable for anything sensitive until you understand each one.",
        ]
    elif severity == "low":
        headline = "Minor changes only — nothing that clearly points to a malicious cable."
        verdict = [
            "These are usually the host reacting to a new device or normal "
            "background activity. Skim the findings; if anything doesn't match "
            "what you plugged in, re-test.",
        ]
    else:  # info / none
        headline = "CableProbe did not observe anything notable this session."
        verdict = [
            "This is NOT the same as \"the cable is safe\". A malicious cable can "
            "stay completely dormant — waiting for a particular computer, a "
            "delay, or a trigger. Read a clean result as \"nothing happened this "
            "time\", not \"nothing can happen\".",
        ]

    body: list[str] = list(verdict)

    themes = _themes_present(report)
    if themes:
        body.append("")
        body.append("What CableProbe saw, in plain terms:")
        body.extend(f"- {t}" for t in themes)

    if persisted:
        body.append("")
        body.append(
            f"Heads up: {persisted} thing(s) that appeared did NOT go away when "
            "the cable was unplugged (the \"DID NOT REVERT\" rows). The host may "
            "still be affected — investigate before trusting it again."
        )

    if severity in ("info", "none") and cable_changes:
        body.append("")
        body.append(
            f"CableProbe did correlate {cable_changes} small change(s) with the "
            "cable; none matched a detection rule. Glance at the table above in "
            "case one is meaningful for your situation."
        )

    body.append("")
    body.append(
        "The table lists every change; the Findings explain why each matters; "
        "the saved JSON report has the raw evidence for a follow-up."
    )
    return Advice(headline=headline, severity=severity, body=body)
