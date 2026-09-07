# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest

from cableprobe.config import Config
from cableprobe.models import KIND_INPUT_DEVICE, Observation
from cableprobe.probes.base import Probe
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


async def test_run_session_requires_probes(fast_config, monkeypatch):
    monkeypatch.setattr(
        "cableprobe.session.build_probes", lambda config, session_start: []
    )
    with pytest.raises(RuntimeError):
        await run_session(
            fast_config, RuleSet.default(), session_name="x", sleep=_noop_sleep
        )


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
