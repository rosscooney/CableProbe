# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from cableprobe.analysis import analyse, build_summary
from cableprobe.models import (
    KIND_BLOCK_DEVICE,
    KIND_INPUT_DEVICE,
    KIND_NETWORK_INTERFACE,
    KIND_USB_DEVICE,
    PHASE_TEST,
)
from tests.conftest import event, obs


def _by_identity(deltas):
    return {d.identity: d for d in deltas}


def test_device_appears_during_test_and_reverts(phase_builder):
    hub = obs(KIND_USB_DEVICE, "usb:1234:5678", "Acme Hub")
    keyboard = obs(KIND_INPUT_DEVICE, "input:aaa", "Evil Keyboard", ID_INPUT_KEYBOARD="1")

    phases = phase_builder(
        baseline_end=[hub],
        test_end=[hub, keyboard],
        post_end=[hub],
    )
    deltas = analyse(phases)
    d = _by_identity(deltas)

    assert set(d) == {"input:aaa"}
    assert d["input:aaa"].change == "appeared"
    assert d["input:aaa"].first_seen_phase == PHASE_TEST
    assert d["input:aaa"].reverted_after_disconnect is True


def test_modification_only_in_post_test_is_detected(phase_builder):
    from cableprobe.models import PHASE_POST_TEST

    before = obs(KIND_BLOCK_DEVICE, "persist:/etc/hosts", "hosts", sha256="aaa")
    after = obs(KIND_BLOCK_DEVICE, "persist:/etc/hosts", "hosts", sha256="bbb")
    # unchanged from baseline through test; rewritten only after disconnect
    phases = phase_builder(baseline_end=[before], test_end=[before], post_end=[after])
    d = _by_identity(analyse(phases))

    assert "persist:/etc/hosts" in d
    assert d["persist:/etc/hosts"].change == "modified"
    assert d["persist:/etc/hosts"].first_seen_phase == PHASE_POST_TEST
    assert any(c.key == "sha256" for c in d["persist:/etc/hosts"].attribute_changes)


def test_change_at_test_start_reverted_by_test_end_is_still_recorded():
    from datetime import datetime, timezone

    from cableprobe.models import PHASE_BASELINE, PHASE_POST_TEST, PHASE_TEST
    from tests.conftest import phase

    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    unchanged = obs(KIND_BLOCK_DEVICE, "persist:/etc/hosts", "hosts", sha256="aaa")
    tampered = obs(KIND_BLOCK_DEVICE, "persist:/etc/hosts", "hosts", sha256="bbb")

    phases = {
        PHASE_BASELINE: phase(PHASE_BASELINE, [unchanged], [unchanged]),
        # rewritten on connect, put back before the phase ended
        PHASE_TEST: phase(PHASE_TEST, [tampered], [unchanged], offset_minutes=2),
        PHASE_POST_TEST: phase(PHASE_POST_TEST, [unchanged], [unchanged], offset_minutes=4),
    }
    d = _by_identity(analyse(phases))
    assert "persist:/etc/hosts" in d
    assert d["persist:/etc/hosts"].change == "modified"
    assert d["persist:/etc/hosts"].first_seen_phase == PHASE_TEST


def test_a_blatant_start_state_change_is_kept_alongside_the_lasting_one():
    from datetime import datetime, timezone

    from cableprobe.models import PHASE_BASELINE, PHASE_POST_TEST, PHASE_TEST
    from cableprobe.analysis import analyse
    from tests.conftest import phase

    a = obs(KIND_BLOCK_DEVICE, "persist:/etc/hosts", "hosts", sha256="AAA")
    blatant = obs(KIND_BLOCK_DEVICE, "persist:/etc/hosts", "hosts", sha256="BBB")
    subtle = obs(KIND_BLOCK_DEVICE, "persist:/etc/hosts", "hosts", sha256="CCC")

    phases = {
        PHASE_BASELINE: phase(PHASE_BASELINE, [a], [a]),
        # BBB at test-start, walked back to a different lasting value CCC
        PHASE_TEST: phase(PHASE_TEST, [blatant], [subtle], offset_minutes=2),
        PHASE_POST_TEST: phase(PHASE_POST_TEST, [subtle], [subtle], offset_minutes=4),
    }
    all_deltas = [d for d in analyse(phases) if d.identity == "persist:/etc/hosts"]
    afters = {
        c.after
        for d in all_deltas
        for c in d.attribute_changes
        if c.key == "sha256"
    }
    assert "BBB" in afters  # the blatant intermediate state is not discarded
    assert "CCC" in afters  # the lasting change too


def test_established_item_deleted_during_post_test_is_recorded(phase_builder):
    from cableprobe.models import PHASE_POST_TEST

    f = obs(KIND_BLOCK_DEVICE, "persist:/etc/ld.so.preload", "preload", sha256="x")
    phases = phase_builder(baseline_end=[f], test_end=[f], post_end=[])
    d = _by_identity(analyse(phases))
    assert d["persist:/etc/ld.so.preload"].change == "disappeared"
    assert d["persist:/etc/ld.so.preload"].first_seen_phase == PHASE_POST_TEST


def test_ephemeral_listener_churn_is_filtered_but_persistent_one_is_kept(phase_builder):
    from cableprobe.models import KIND_LISTENING_SOCKET

    def sock(port, ephemeral):
        return obs(
            KIND_LISTENING_SOCKET, f"listen:tcp:0.0.0.0:{port}",
            f"tcp listening on 0.0.0.0:{port}",
            protocol="tcp", port=port, ephemeral_port=ephemeral,
        )

    phases = phase_builder(
        baseline_end=[sock(45001, True), sock(4444, False)],
        test_end=[sock(46002, True), sock(47003, True)],
        post_end=[sock(46002, True)],
    )
    d = _by_identity(analyse(phases))
    # the baseline ephemeral listener that simply closed -> not a phase difference
    assert "listen:tcp:0.0.0.0:45001" not in d
    # a high port seen in only the test snapshot -> throwaway socket, not signal
    assert "listen:tcp:0.0.0.0:47003" not in d
    # a fixed-port listener that disappeared is still real signal
    assert d["listen:tcp:0.0.0.0:4444"].change == "disappeared"
    # a NEW ephemeral listener present across two snapshots (test + post) is kept
    assert d["listen:tcp:0.0.0.0:46002"].change == "appeared"


def test_power_series_spike_during_test_produces_a_delta(phase_builder):
    from cableprobe.models import KIND_POWER_SERIES

    def series(label, **attrs):
        base = dict(
            spike_count=0, max_current_ma=90, alert_threshold_ma=8, baseline_ma=90,
            current_spike=False, sustained_excess=False, voltage_excursion=False,
        )
        base.update(attrs)
        return obs(KIND_POWER_SERIES, "power:series", label, **base)

    phases = phase_builder(
        baseline_end=[series("flat")],
        test_end=[series("spiky", spike_count=3, max_current_ma=260, current_spike=True)],
        post_end=[series("flat")],
    )
    d = _by_identity(analyse(phases))
    assert d["power:series:test"].first_seen_phase == "test"
    assert d["power:series:test"].kind == KIND_POWER_SERIES
    assert d["power:series:test"].attributes["spikes_above_baseline"] == 3
    # the raw per-phase telemetry is not itself emitted as a modified delta
    assert "power:series" not in d
    # a clean post-test waveform matching baseline produces nothing
    assert "power:series:post_test" not in d


def test_power_series_no_delta_when_waveform_matches_baseline(phase_builder):
    from cableprobe.models import KIND_POWER_SERIES

    flat = obs(
        KIND_POWER_SERIES, "power:series", "flat",
        spike_count=0, max_current_ma=90, alert_threshold_ma=8, baseline_ma=90,
        current_spike=False, sustained_excess=False, voltage_excursion=False,
    )
    phases = phase_builder(baseline_end=[flat], test_end=[flat], post_end=[flat])
    assert not any(dd.kind == KIND_POWER_SERIES for dd in analyse(phases))


def test_chameleon_reenumeration_is_caught_even_though_it_reverts(phase_builder):
    # a cable that enumerates as a boring flash drive, briefly re-enumerates as
    # a keyboard, then drops back to the flash drive shape - all within the
    # test phase. Both phase-boundary snapshots see only the flash drive.
    events = [
        event(
            "add", KIND_USB_DEVICE, "usb:1-2", "Boring Flash Drive",
            ID_VENDOR_ID="0951", ID_MODEL_ID="1666", ID_USB_INTERFACES=":080650:",
        ),
        event("remove", KIND_USB_DEVICE, "usb:1-2", "Boring Flash Drive"),
        event(
            "add", KIND_USB_DEVICE, "usb:1-2", "Evil Keyboard",
            ID_VENDOR_ID="046d", ID_MODEL_ID="c31c", ID_USB_INTERFACES=":030101:",
        ),
        event("remove", KIND_USB_DEVICE, "usb:1-2", "Evil Keyboard"),
        event(
            "add", KIND_USB_DEVICE, "usb:1-2", "Boring Flash Drive",
            ID_VENDOR_ID="0951", ID_MODEL_ID="1666", ID_USB_INTERFACES=":080650:",
        ),
    ]
    disk = obs(
        KIND_USB_DEVICE, "usb:1-2", "Boring Flash Drive",
        ID_VENDOR_ID="0951", ID_MODEL_ID="1666", ID_USB_INTERFACES=":080650:",
    )
    phases = phase_builder(
        baseline_end=[], test_end=[disk], post_end=[], test_events=events,
    )

    deltas = analyse(phases)
    chameleon = next(d for d in deltas if d.attributes.get("chameleon_shape_count"))
    assert chameleon.kind == KIND_USB_DEVICE
    assert chameleon.identity == "usb:1-2"
    assert chameleon.first_seen_phase == PHASE_TEST
    assert chameleon.attributes["chameleon_shape_count"] == 2
    changed_keys = {c.key for c in chameleon.attribute_changes}
    assert "ID_USB_INTERFACES" in changed_keys
    assert "ID_VENDOR_ID" in changed_keys
    # the normal appeared delta for the settled (reverted) shape is untouched
    settled = next(d for d in deltas if d.identity == "usb:1-2" and d.change == "appeared")
    assert settled.reverted_after_disconnect is True


def test_chameleon_reenumeration_ignores_a_single_shape(phase_builder):
    # one add event, or repeated adds of the SAME shape - not a chameleon
    events = [
        event(
            "add", KIND_USB_DEVICE, "usb:1-3", "Normal Mouse",
            ID_VENDOR_ID="046d", ID_MODEL_ID="c077", ID_USB_INTERFACES=":030102:",
        ),
        event(
            "change", KIND_USB_DEVICE, "usb:1-3", "Normal Mouse",
            ID_VENDOR_ID="046d", ID_MODEL_ID="c077", ID_USB_INTERFACES=":030102:",
        ),
    ]
    mouse = obs(
        KIND_USB_DEVICE, "usb:1-3", "Normal Mouse",
        ID_VENDOR_ID="046d", ID_MODEL_ID="c077", ID_USB_INTERFACES=":030102:",
    )
    phases = phase_builder(
        baseline_end=[], test_end=[mouse], post_end=[mouse], test_events=events,
    )
    deltas = analyse(phases)
    assert not any(d.attributes.get("chameleon_shape_count") for d in deltas)


def test_chameleon_reenumeration_ignores_a_partially_populated_event(phase_builder):
    # the very first add on a fresh plug can have incomplete udev properties
    # while the database enrichment settles - must not look like a second shape
    events = [
        event(
            "add", KIND_USB_DEVICE, "usb:1-4", "Settling Device",
            ID_VENDOR_ID="1234", ID_MODEL_ID="5678",
        ),  # ID_USB_INTERFACES not populated yet
        event(
            "change", KIND_USB_DEVICE, "usb:1-4", "Settling Device",
            ID_VENDOR_ID="1234", ID_MODEL_ID="5678", ID_USB_INTERFACES=":ff0000:",
        ),
    ]
    dev = obs(
        KIND_USB_DEVICE, "usb:1-4", "Settling Device",
        ID_VENDOR_ID="1234", ID_MODEL_ID="5678", ID_USB_INTERFACES=":ff0000:",
    )
    phases = phase_builder(
        baseline_end=[], test_end=[dev], post_end=[dev], test_events=events,
    )
    deltas = analyse(phases)
    assert not any(d.attributes.get("chameleon_shape_count") for d in deltas)


def test_transient_ephemeral_listener_does_not_reach_the_rules():
    from cableprobe.models import KIND_LISTENING_SOCKET, PHASE_BASELINE, PHASE_POST_TEST, PHASE_TEST
    from tests.conftest import phase

    def sock(port):
        return obs(
            KIND_LISTENING_SOCKET, f"listen:tcp:0.0.0.0:{port}",
            f"tcp listening on 0.0.0.0:{port}",
            protocol="tcp", port=port, ephemeral_port=True,
        )

    churn = sock(40121)
    phases = {
        PHASE_BASELINE: phase(PHASE_BASELINE, [], []),
        PHASE_TEST: phase(PHASE_TEST, [churn], [], offset_minutes=2),  # up at start, gone by end
        PHASE_POST_TEST: phase(PHASE_POST_TEST, [], [], offset_minutes=4),
    }
    deltas = analyse(phases)
    assert not any(d.kind == KIND_LISTENING_SOCKET for d in deltas)


def test_item_that_vanishes_and_returns_within_test_is_recorded():
    from datetime import datetime, timezone

    from cableprobe.models import PHASE_BASELINE, PHASE_POST_TEST, PHASE_TEST
    from tests.conftest import phase

    f = obs(KIND_BLOCK_DEVICE, "persist:/etc/hosts", "hosts", sha256="x")
    phases = {
        PHASE_BASELINE: phase(PHASE_BASELINE, [f], [f]),
        PHASE_TEST: phase(PHASE_TEST, [], [f], offset_minutes=2),  # gone at start
        PHASE_POST_TEST: phase(PHASE_POST_TEST, [f], [f], offset_minutes=4),
    }
    d = _by_identity(analyse(phases))
    assert d["persist:/etc/hosts"].change == "disappeared"
    assert d["persist:/etc/hosts"].first_seen_phase == PHASE_TEST


def test_plug_and_vanish_during_post_test_is_transient(phase_builder):
    from cableprobe.models import PHASE_POST_TEST

    phases = phase_builder(
        baseline_end=[],
        test_end=[],
        post_end=[],
        post_events=[
            event("add", KIND_USB_DEVICE, "usb:dead:beef", "ghost"),
            event("remove", KIND_USB_DEVICE, "usb:dead:beef", "ghost"),
        ],
    )
    d = _by_identity(analyse(phases))
    assert d["usb:dead:beef"].transient is True
    assert d["usb:dead:beef"].first_seen_phase == PHASE_POST_TEST


def test_device_appears_and_persists(phase_builder):
    keyboard = obs(KIND_INPUT_DEVICE, "input:aaa", "Sticky Keyboard")
    phases = phase_builder(baseline_end=[], test_end=[keyboard], post_end=[keyboard])
    (delta,) = analyse(phases)
    assert delta.change == "appeared"
    assert delta.reverted_after_disconnect is False


def test_device_disappears_during_test(phase_builder):
    eth = obs(KIND_NETWORK_INTERFACE, "net:eth0", "eth0")
    phases = phase_builder(baseline_end=[eth], test_end=[], post_end=[eth])
    (delta,) = analyse(phases)
    assert delta.change == "disappeared"
    assert delta.reverted_after_disconnect is True


def test_modified_attribute(phase_builder):
    before = obs(KIND_NETWORK_INTERFACE, "net:eth0", "eth0", is_up=False)
    after = obs(KIND_NETWORK_INTERFACE, "net:eth0", "eth0", is_up=True)
    phases = phase_builder(baseline_end=[before], test_end=[after], post_end=[after])
    (delta,) = analyse(phases)
    assert delta.change == "modified"
    assert delta.attribute_changes[0].key == "is_up"
    assert delta.attribute_changes[0].before is False
    assert delta.attribute_changes[0].after is True


def test_volatile_attributes_do_not_trigger_modified(phase_builder):
    before = obs(KIND_USB_DEVICE, "usb:1:2", "Dev", devnum="3", create_time=1.0)
    after = obs(KIND_USB_DEVICE, "usb:1:2", "Dev", devnum="9", create_time=2.0)
    phases = phase_builder(baseline_end=[before], test_end=[after], post_end=[after])
    assert analyse(phases) == []


def test_probe_bookkeeping_attributes_are_volatile(phase_builder):
    # a kernel module's refcount and a socket's inode churn on their own
    before = obs("kernel_module", "kmod:xhci_hcd", "xhci_hcd", refcount=2, state="Live")
    after = obs("kernel_module", "kmod:xhci_hcd", "xhci_hcd", refcount=5, state="Live")
    phases = phase_builder(baseline_end=[before], test_end=[after], post_end=[after])
    assert analyse(phases) == []

    # but a real state change still registers
    b2 = obs("kernel_module", "kmod:xhci_hcd", "xhci_hcd", refcount=2, used_by=[])
    a2 = obs("kernel_module", "kmod:xhci_hcd", "xhci_hcd", refcount=2, used_by=["evil"])
    phases2 = phase_builder(baseline_end=[b2], test_end=[a2], post_end=[a2])
    (delta,) = analyse(phases2)
    assert delta.attribute_changes[0].key == "used_by"


def test_unchanged_devices_produce_no_delta(phase_builder):
    dev = obs(KIND_USB_DEVICE, "usb:1:2", "Dev")
    phases = phase_builder(baseline_end=[dev], test_end=[dev], post_end=[dev])
    assert analyse(phases) == []


def test_transient_device_from_events(phase_builder):
    phases = phase_builder(
        baseline_end=[],
        test_end=[],
        post_end=[],
        test_events=[
            event("add", KIND_INPUT_DEVICE, "input:ghost", "Ghost HID"),
            event("remove", KIND_INPUT_DEVICE, "input:ghost", "Ghost HID"),
        ],
    )
    (delta,) = analyse(phases)
    assert delta.transient is True
    assert delta.change == "appeared"
    assert delta.first_seen_phase == PHASE_TEST
    assert delta.reverted_after_disconnect is True


def test_add_only_event_is_not_transient(phase_builder):
    # a USB disk fires a burst of `add` events (scsi_*, bsg, ...) and stays; it
    # is removed only in post-test. That is not a plug-and-vanish.
    disk = obs(KIND_BLOCK_DEVICE, "block:SERIAL1", "the disk")
    phases = phase_builder(
        baseline_end=[],
        test_end=[disk],
        post_end=[],
        test_events=[
            event("add", KIND_BLOCK_DEVICE, "TOSHIBA_MODEL", "TOSHIBA_MODEL"),
        ],
    )
    deltas = analyse(phases)
    # one normal "appeared" for the disk; NO transient delta for the stray add
    assert [(d.identity, d.transient) for d in deltas] == [("block:SERIAL1", False)]


def test_post_test_only_appearance(phase_builder):
    dev = obs(KIND_USB_DEVICE, "usb:9:9", "Delayed")
    phases = phase_builder(baseline_end=[], test_end=[], post_end=[dev])
    (delta,) = analyse(phases)
    assert delta.first_seen_phase == "post_test"
    assert delta.reverted_after_disconnect is False


def test_build_summary_counts(phase_builder):
    kb = obs(KIND_INPUT_DEVICE, "input:aaa", "kbd", ID_INPUT_KEYBOARD="1")
    phases = phase_builder(baseline_end=[], test_end=[kb], post_end=[kb])
    deltas = analyse(phases)
    summary = build_summary(phases, deltas, [])
    assert summary["delta_count"] == 1
    assert summary["cable_correlated_change_count"] == 1
    assert summary["persisted_after_disconnect_count"] == 1
    assert summary["highest_severity"] is None


def test_persisted_count_ignores_kernel_log_and_process_noise(phase_builder):
    # kernel log lines and processes never "revert" - they must not inflate the
    # "did not revert" heads-up
    kmsg = obs("kernel_message", "kmsg:usb # new device", "usb 1-1: new device")
    proc = obs("process", "proc:1:sleep", "process sleep")
    dev = obs(KIND_USB_DEVICE, "usb:1:2", "Sticky device")
    phases = phase_builder(
        baseline_end=[],
        test_end=[kmsg, proc, dev],
        post_end=[kmsg, proc, dev],  # all still "present"
    )
    summary = build_summary(phases, analyse(phases), [])
    assert summary["persisted_after_disconnect_count"] == 1  # only the usb_device
