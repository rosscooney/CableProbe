# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest

from cableprobe.config import Config
from cableprobe.models import KIND_INPUT_DEVICE, Observation
from cableprobe.probes.base import Probe, ProbeAvailability
from cableprobe.rules import RuleSet
from cableprobe.session import run_session


class FakeProbe(Probe):
    name = "fake"

    def __init__(self, config, session_start, script):
        super().__init__(config, session_start)
        self._script = script  # list of observation-lists, consumed per snapshot
        self._calls = 0

    def snapshot(self) -> list[Observation]:
        idx = min(self._calls, len(self._script) - 1)
        self._calls += 1
        return list(self._script[idx])


@pytest.fixture
def fast_config():
    return Config.model_validate(
        {
            "session": {
                "baseline_seconds": 1,
                "test_seconds": 1,
                "post_test_seconds": 1,
                "sample_interval_seconds": 1,
                "interactive": False,
            }
        }
    )


async def _noop_sleep(_seconds):
    return None


async def test_run_session_detects_cable_correlated_device(fast_config, monkeypatch):
    kb = Observation(
        kind=KIND_INPUT_DEVICE,
        identity="input:evil",
        label="Evil Keyboard",
        attributes={"ID_INPUT_KEYBOARD": "1"},
    )
    # _observe_phase takes 3 snapshots per phase (start, one tick, end):
    # baseline -> [], test -> [kb], post -> []
    script = [[]] * 3 + [[kb]] * 3 + [[]] * 3
    fake = FakeProbe(fast_config, 0.0, script)

    monkeypatch.setattr(
        "cableprobe.session.build_probes", lambda config, session_start: [fake]
    )

    prompts: list[str] = []

    report = await run_session(
        fast_config,
        RuleSet.default(),
        session_name="test",
        prompt_fn=lambda phase, message: prompts.append(phase),
        sleep=_noop_sleep,
    )

    assert prompts == ["baseline", "test", "post_test"]
    assert report.metadata.probes_used == ["fake"]
    identities = {d.identity for d in report.deltas}
    assert "input:evil" in identities
    delta = next(d for d in report.deltas if d.identity == "input:evil")
    assert delta.first_seen_phase == "test"
    assert delta.reverted_after_disconnect is True
    assert any(f.rule_id == "hid-keyboard-appeared-on-connect" for f in report.findings)
    assert report.summary["highest_severity"] == "high"


async def test_run_session_applies_implants_and_allowlist(fast_config, monkeypatch):
    from cableprobe.knowledge import Allowlist, ImplantList
    from cableprobe.models import KIND_USB_DEVICE

    implant = Observation(
        kind=KIND_USB_DEVICE,
        identity="usb:16d0:0753",
        label="Digispark",
        attributes={"vendor_id": "16d0", "product_id": "0753", "serial": "X1"},
    )
    fake = FakeProbe(fast_config, 0.0, [[]] * 3 + [[implant]] * 3 + [[]] * 3)
    monkeypatch.setattr(
        "cableprobe.session.build_probes", lambda config, session_start: [fake]
    )

    report = await run_session(
        fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep,
        implants=ImplantList.load(),
    )
    assert any(f.rule_id == "known-implant-device" for f in report.findings)

    # now allowlist that exact device -> the implant finding is downgraded
    al = Allowlist([], None)
    al.add("16d0", "0753", "X1", "my dev board")
    fake2 = FakeProbe(fast_config, 0.0, [[]] * 3 + [[implant]] * 3 + [[]] * 3)
    monkeypatch.setattr(
        "cableprobe.session.build_probes", lambda config, session_start: [fake2]
    )
    report2 = await run_session(
        fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep,
        implants=ImplantList.load(), allowlist=al,
    )
    implant_finding = next(
        f for f in report2.findings if f.rule_id == "known-implant-device"
    )
    assert implant_finding.severity == "info"
    assert "allowlisted: my dev board" in implant_finding.title


async def test_run_session_requires_probes(fast_config, monkeypatch):
    monkeypatch.setattr(
        "cableprobe.session.build_probes", lambda config, session_start: []
    )
    with pytest.raises(RuntimeError):
        await run_session(
            fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep
        )


async def test_unavailable_probe_is_skipped_not_warned(fast_config, monkeypatch):
    kb = Observation(kind=KIND_INPUT_DEVICE, identity="input:x", label="kb")
    working = FakeProbe(fast_config, 0.0, [[]] * 3 + [[kb]] * 3 + [[]] * 3)

    class NoTypeC(Probe):
        name = "usbc_pd"

        def availability(self):
            return ProbeAvailability(ok=False, detail="/sys/class/typec not present")

        def snapshot(self):
            raise AssertionError("unavailable probe should not be snapshotted")

    monkeypatch.setattr(
        "cableprobe.session.build_probes",
        lambda config, session_start: [NoTypeC(fast_config, 0.0), working],
    )
    report = await run_session(
        fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep
    )
    assert report.metadata.probes_used == ["fake"]
    assert report.metadata.probe_warnings == []
    assert any("usbc_pd" in u for u in report.metadata.probes_unavailable)


async def test_run_session_all_probes_unavailable(fast_config, monkeypatch):
    class Dead(Probe):
        name = "dead"

        def availability(self):
            return ProbeAvailability(ok=False, detail="nope")

        def snapshot(self):
            return []

    monkeypatch.setattr(
        "cableprobe.session.build_probes",
        lambda config, session_start: [Dead(fast_config, 0.0)],
    )
    with pytest.raises(RuntimeError, match="no enabled probe can run"):
        await run_session(
            fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep
        )


async def test_new_signals_flow_through_to_findings(fast_config, monkeypatch):
    from cableprobe.models import (
        KIND_KEYSTROKE_TIMING,
        KIND_PCI_DEVICE,
        KIND_USB_INTERFACE,
    )

    appeared = [
        Observation(
            kind=KIND_PCI_DEVICE,
            identity="pci:0000:00:1c.4",
            label="PCI device tunnelled in",
        ),
        Observation(
            kind=KIND_USB_INTERFACE,
            identity="usbif:dead:beef:x:00",
            label="hid interface #00",
            attributes={"interface_class_name": "hid"},
        ),
        Observation(
            kind=KIND_KEYSTROKE_TIMING,
            identity="kbdtiming:event5",
            label="key-press timing — LOOKS INJECTED",
            attributes={"looks_injected": True, "keystrokes": 200},
        ),
    ]
    script = [[]] * 3 + [list(appeared)] * 3 + [[]] * 3
    fake = FakeProbe(fast_config, 0.0, script)
    monkeypatch.setattr(
        "cableprobe.session.build_probes", lambda config, session_start: [fake]
    )

    report = await run_session(
        fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep
    )
    by_rule = {f.rule_id: f.severity for f in report.findings}
    assert by_rule.get("pci-device-appeared-on-connect") == "critical"
    assert by_rule.get("hid-interface-appeared-on-connect") == "high"
    assert by_rule.get("keystroke-injection-detected") == "critical"
    assert report.summary["highest_severity"] == "critical"


async def test_probe_snapshot_failure_is_recorded(fast_config, monkeypatch):
    class BrokenProbe(Probe):
        name = "broken"

        def snapshot(self):
            raise OSError("boom")

    broken = BrokenProbe(fast_config, 0.0)
    monkeypatch.setattr(
        "cableprobe.session.build_probes", lambda config, session_start: [broken]
    )
    report = await run_session(
        fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep
    )
    # session still completes; errors captured on snapshots
    assert any(
        "broken: boom" in err
        for phase in report.phases.values()
        for err in phase.end_snapshot.errors
    )
