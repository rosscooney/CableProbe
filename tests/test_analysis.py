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
