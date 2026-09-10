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


async def test_observe_phase_keeps_lead_in_events(fast_config):
    from cableprobe.session import _observe_phase
    from tests.conftest import event as _event

    class QueuedEvent(Probe):
        name = "q"

        def __init__(self):
            super().__init__(fast_config, 0.0)
            self._pending = [_event("add", "usb_device", "usb:x", "x")]

        def snapshot(self):
            return []

        def drain_events(self):
            out, self._pending = self._pending, []
            return out

    # the event was queued before the phase loop starts (the "connect now" prompt)
    result = await _observe_phase(
        [QueuedEvent()], "test", 1.0, 1.0, sleep=_noop_sleep
    )
    assert [e.identity for e in result.events] == ["usb:x"]


async def test_observe_phase_caps_an_event_storm(fast_config, monkeypatch):
    from cableprobe.session import _observe_phase
    from tests.conftest import event as _event

    monkeypatch.setattr("cableprobe.session._MAX_PHASE_EVENTS", 50)

    class Flood(Probe):
        name = "flood"

        def snapshot(self):
            return []

        def drain_events(self):
            return [_event("add", "usb_device", f"usb:{i}", "x") for i in range(200)]

    result = await _observe_phase(
        [Flood(fast_config, 0.0)], "test", 1.0, 1.0, sleep=_noop_sleep
    )
    assert len(result.events) == 50
    assert result.events_dropped >= 150


async def test_run_session_detects_cable_correlated_device(fast_config, monkeypatch):
    kb = Observation(
        kind=KIND_INPUT_DEVICE,
        identity="input:evil",
        label="Evil Keyboard",
        attributes={"ID_INPUT_KEYBOARD": "1"},
    )
    # _observe_phase takes 2 snapshots per phase (start, end):
    # baseline -> [], test -> [kb], post -> []
    script = [[]] * 2 + [[kb]] * 2 + [[]] * 2
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
    fake = FakeProbe(fast_config, 0.0, [[]] * 2 + [[implant]] * 2 + [[]] * 2)
    monkeypatch.setattr(
        "cableprobe.session.build_probes", lambda config, session_start: [fake]
    )

    report = await run_session(
        fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep,
        implants=ImplantList.load(),
    )
    assert any(f.rule_id == "known-implant-device" for f in report.findings)

    # allowlisting a device whose ID is a known attack tool is a contradiction:
    # the finding stays loud but is annotated, never silently downgraded.
    al = Allowlist([], None)
    al.add("16d0", "0753", "X1", "my dev board")
    fake2 = FakeProbe(fast_config, 0.0, [[]] * 2 + [[implant]] * 2 + [[]] * 2)
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
    assert implant_finding.severity != "info"
    assert "also on your allowlist: my dev board" in implant_finding.title


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
    working = FakeProbe(fast_config, 0.0, [[]] * 2 + [[kb]] * 2 + [[]] * 2)

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


async def test_review_warning_only_when_a_secret_was_masked(fast_config, monkeypatch):
    from cableprobe.models import KIND_PROCESS

    plain = Observation(
        kind=KIND_PROCESS, identity="proc:1", label="p", attributes={"cmdline": "sh -c true"}
    )
    masked = Observation(
        kind=KIND_PROCESS,
        identity="proc:2",
        label="p",
        attributes={"cmdline": "app --token ***"},
    )

    class FakeProcess(FakeProbe):
        name = "process"

    monkeypatch.setattr(
        "cableprobe.session.build_probes",
        lambda config, session_start: [FakeProcess(fast_config, 0.0, [[plain]] * 6)],
    )
    r1 = await run_session(fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep)
    assert r1.metadata.probe_warnings == []  # nothing was masked -> no noise

    monkeypatch.setattr(
        "cableprobe.session.build_probes",
        lambda config, session_start: [FakeProcess(fast_config, 0.0, [[masked]] * 6)],
    )
    r2 = await run_session(fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep)
    assert any("masked" in w and "sharing" in w for w in r2.metadata.probe_warnings)

    fast_config.probes.capture_process_cmdline = False
    r3 = await run_session(fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep)
    assert r3.metadata.probe_warnings == []


async def test_timed_out_probe_is_quarantined_not_rescheduled(fast_config, monkeypatch):
    import time as _time

    monkeypatch.setattr("cableprobe.session._SNAPSHOT_TIMEOUT", 0.05)

    calls = {"n": 0}

    class Slow(Probe):
        name = "slow"

        def snapshot(self):
            calls["n"] += 1
            _time.sleep(0.4)  # exceeds the (patched) deadline every time
            return []

    quiet = FakeProbe(fast_config, 0.0, [[]] * 6)
    monkeypatch.setattr(
        "cableprobe.session.build_probes",
        lambda config, session_start: [Slow(fast_config, 0.0), quiet],
    )
    report = await run_session(
        fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep
    )

    assert "slow" in report.metadata.probe_snapshot_errors
    assert "quarantin" in report.metadata.probe_snapshot_errors["slow"]
    # 6 snapshots would be taken without quarantine; it should stop after ~1
    assert calls["n"] <= 2


async def test_a_start_failure_alone_makes_coverage_partial(fast_config, monkeypatch):
    from cableprobe.report import exit_code_for

    kb = Observation(kind=KIND_INPUT_DEVICE, identity="input:x", label="kb")
    quiet = FakeProbe(fast_config, 0.0, [[]] * 6)

    class WontStart(Probe):
        name = "udev_monitor"

        async def start(self):
            raise RuntimeError("no netlink")

        def snapshot(self):
            return []

    monkeypatch.setattr(
        "cableprobe.session.build_probes",
        lambda config, session_start: [WontStart(fast_config, 0.0), quiet],
    )
    report = await run_session(
        fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep
    )
    assert report.summary["coverage"] == "partial"
    assert "udev_monitor" in report.summary["coverage_gaps"]["probes_failed_to_start"]
    assert exit_code_for(report) == 5


async def test_snapshot_failures_flag_incomplete_coverage(fast_config, monkeypatch):
    from cableprobe.advice import build_advice
    from cableprobe.report import exit_code_for

    quiet = FakeProbe(fast_config, 0.0, [[]] * 6)  # a working probe, no findings

    class Flaky(Probe):
        name = "flaky"

        def snapshot(self):
            raise RuntimeError("sysfs went away")

    monkeypatch.setattr(
        "cableprobe.session.build_probes",
        lambda config, session_start: [Flaky(fast_config, 0.0), quiet],
    )
    report = await run_session(
        fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep
    )

    assert "flaky" in report.metadata.probe_snapshot_errors
    assert "sysfs went away" in report.metadata.probe_snapshot_errors["flaky"]
    assert report.summary["coverage"] == "partial"

    advice = build_advice(report)
    assert "not conclusive" in advice.headline.lower()
    assert advice.severity != "none"  # no green all-clear
    assert any("flaky" in line for line in advice.body)

    assert exit_code_for(report) == 5  # inconclusive, not clean


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
    script = [[]] * 2 + [list(appeared)] * 2 + [[]] * 2
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
