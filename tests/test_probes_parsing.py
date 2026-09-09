# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from cableprobe.models import (
    KIND_BLOCK_DEVICE,
    KIND_INPUT_DEVICE,
    KIND_KERNEL_MESSAGE,
    KIND_USB_DEVICE,
)
from cableprobe.probes.block import parse_lsblk_json
from cableprobe.probes.input_devices import parse_proc_input
from cableprobe.probes.kernel_log import filter_kernel_lines
from cableprobe.probes.usb import _interface_classes, parse_lsusb

LSUSB_SAMPLE = """\
Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 001 Device 004: ID 046d:c52b Logitech, Inc. Unifying Receiver
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
"""


def test_parse_lsusb():
    out = parse_lsusb(LSUSB_SAMPLE)
    assert len(out) == 3
    logi = next(o for o in out if o.identity == "usb:046d:c52b")
    assert logi.kind == KIND_USB_DEVICE
    assert "Logitech" in logi.label
    assert logi.attributes["vendor_id"] == "046d"


def test_interface_classes_decode():
    assert _interface_classes(":030102:080650:") == ["hid", "mass-storage"]
    assert _interface_classes(None) == []


LSBLK_SAMPLE = {
    "blockdevices": [
        {
            "name": "mmcblk0",
            "path": "/dev/mmcblk0",
            "type": "disk",
            "size": "29.7G",
            "rm": False,
            "hotplug": False,
            "tran": None,
            "children": [
                {"name": "mmcblk0p1", "path": "/dev/mmcblk0p1", "type": "part", "size": "256M"},
            ],
        },
        {
            "name": "sda",
            "path": "/dev/sda",
            "type": "disk",
            "size": "16G",
            "rm": True,
            "hotplug": True,
            "tran": "usb",
            "serial": "AA11BB22",
            "vendor": "SanDisk",
            "model": "Cruzer",
        },
    ]
}


def test_parse_lsblk_json():
    out = parse_lsblk_json(LSBLK_SAMPLE)
    ids = {o.identity for o in out}
    assert "block:AA11BB22" in ids  # keyed by serial when present
    assert "block:mmcblk0" in ids
    sda = next(o for o in out if o.identity == "block:AA11BB22")
    assert sda.kind == KIND_BLOCK_DEVICE
    assert sda.attributes["transport"] == "usb"
    assert sda.attributes["removable"] is True
    # partitions are not emitted as their own observation - summarised on the disk
    assert "block:mmcblk0p1" not in ids
    disk = next(o for o in out if o.identity == "block:mmcblk0")
    assert disk.attributes["partitions"] == ["mmcblk0p1"]
    assert disk.attributes["partition_count"] == 1


PROC_INPUT_SAMPLE = """\
I: Bus=0003 Vendor=046d Product=c52b Version=0111
N: Name="Logitech USB Receiver"
P: Phys=usb-0000:01:00.0-1.2/input0
S: Sysfs=/devices/pci0000:00/0000:01:00.0/usb1/1-1/1-1.2/1-1.2:1.0/input/input5
U: Uniq=
H: Handlers=sysrq kbd event3 leds
B: EV=120013

I: Bus=0003 Vendor=046d Product=c52b Version=0111
N: Name="Logitech USB Receiver Mouse"
P: Phys=usb-0000:01:00.0-1.2/input1
S: Sysfs=/devices/pci0000:00/0000:01:00.0/usb1/1-1/1-1.2/1-1.2:1.1/input/input6
H: Handlers=mouse0 event4
B: EV=17
"""


def test_parse_proc_input():
    out = parse_proc_input(PROC_INPUT_SAMPLE)
    assert len(out) == 2
    kb = out[0]
    assert kb.kind == KIND_INPUT_DEVICE
    assert kb.attributes["ID_INPUT_KEYBOARD"] == "1"
    assert "keyboard" in kb.attributes["capabilities"]
    mouse = out[1]
    assert "mouse" in mouse.attributes["capabilities"]
    assert mouse.attributes["ID_INPUT_MOUSE"] == "1"


def test_filter_kernel_lines():
    lines = [
        "2026-01-01T12:00:01 host kernel: usb 1-1: new high-speed USB device number 5 using xhci_hcd",
        "2026-01-01T12:00:01 host kernel: usb 1-1: device descriptor read/64, error -71",
        "2026-01-01T12:00:02 host systemd: Started something unrelated",
        "2026-01-01T12:00:03 host kernel: cdc_ether 1-1:2.0 usb0: register 'cdc_ether'",
    ]
    out = filter_kernel_lines(lines, ["usb", "cdc_ether", "-71"])
    kinds = {o.kind for o in out}
    assert kinds == {KIND_KERNEL_MESSAGE}
    assert len(out) == 3  # the systemd line is dropped
    assert any("cdc_ether" in o.label for o in out)
    # digits are normalised so repeated lines with different numbers dedupe
    assert all("#" in o.attributes["normalised"] for o in out)


def test_filter_kernel_lines_dedupes_normalised():
    lines = [
        "kernel: usb 1-1: new high-speed USB device number 5",
        "kernel: usb 1-1: new high-speed USB device number 6",
    ]
    out = filter_kernel_lines(lines, ["usb"])
    assert len(out) == 1
