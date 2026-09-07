# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from cableprobe.analysis import analyse, build_summary
from cableprobe.models import (
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
