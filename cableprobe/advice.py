# Copyright (c) 2026-present Stable State Consulting Ltd
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
        "network-hijack",
        ("default-route-changed", "dns-resolvers-changed"),
        "The cable brought up a network adapter AND changed where this "
        "computer's traffic or name-lookups go. Something inside the cable is "
        "now positioned to read, redirect or fake the sites and services you "
        "connect to. This is an active attack, not just a capability.",
    ),
    (
        "network",
        ("network-interface", "rndis-gadget"),
        "The cable made the computer think a network adapter was plugged in. A "
        "cable that does this can sit between you and the internet and read, "
        "redirect or fake the sites and services you connect to. It did not "
        "take over routing here, but a plain charge/data cable has no reason to "
        "add a network adapter at all.",
    ),
    (
        "reboot-persistence",
        ("persistence-point-changed", "persistence-point-removed",
         "persistence-item-became-unreadable"),
        "A file that controls what your computer runs at boot, on a device "
        "event, or at login (a startup service, a udev rule, cron, "
        "authorized_keys, /etc/hosts) changed or was removed while CableProbe "
        "was watching. This is how something makes itself survive a reboot. "
        "CableProbe can't prove the cable did it, but review that exact change "
        "before you trust this machine again.",
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


#: When the key on the left is present, the keys on the right are redundant.
_THEME_SUPERSEDES = {"network-hijack": {"network"}}


def _themes_present(report: SessionReport) -> list[str]:
    rule_ids = {f.rule_id for f in report.findings}
    matched = {
        key
        for key, needles, _ in _THEMES
        if any(n in rid for rid in rule_ids for n in needles)
    }
    superseded = {s for key in matched for s in _THEME_SUPERSEDES.get(key, ())}
    return [
        sentence
        for key, _, sentence in _THEMES
        if key in matched and key not in superseded
    ]


def _failed_probes(report: SessionReport) -> list[str]:
    """Probes that started but could not observe (or failed to start)."""

    failed = set(report.metadata.probe_snapshot_errors)
    failed |= {
        w.split(":", 1)[0].strip()
        for w in report.metadata.probe_warnings
        if "failed to start" in w
    }
    return sorted(failed)


def build_advice(report: SessionReport) -> Advice:
    severity = report.summary.get("highest_severity") or "none"
    persisted = int(report.summary.get("persisted_after_disconnect_count") or 0)
    cable_changes = int(report.summary.get("cable_correlated_change_count") or 0)
    failed_probes = _failed_probes(report)
    partial_coverage = report.summary.get("coverage") == "partial"

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
    elif failed_probes or partial_coverage:
        headline = "Coverage was incomplete — this result is not conclusive."
        verdict = [
            "Some monitoring did not run to completion this session (a probe "
            "failed, an event storm overran a buffer, or a watched file could "
            "not be read), so CableProbe was not watching everything it "
            "normally would. A quiet result here does not mean nothing "
            "happened. Fix the gaps below (often: run as root, or install a "
            "missing tool) and test again.",
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

    if failed_probes or partial_coverage:
        gaps = report.summary.get("coverage_gaps") or {}
        detail = report.metadata.probe_snapshot_errors
        lines = [f"- {n}: {detail.get(n, 'failed to start')}" for n in failed_probes]
        if int(report.summary.get("events_dropped") or 0):
            lines.append(f"- {report.summary['events_dropped']} event(s) dropped")
        for item in gaps.get("incomplete_data", []):
            lines.append(f"- incomplete monitoring: {item}")
        if lines:
            body.append("")
            body.append("Gaps in this session's monitoring:")
            body.extend(lines)

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
    # incomplete coverage must not render as a green "all clear"
    if (failed_probes or partial_coverage) and severity in ("none", "info"):
        severity = "low"
    return Advice(headline=headline, severity=severity, body=body)
