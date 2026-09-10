# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Parser / scanner tests for the probes added after v0.1.

Every probe keeps a pure function (parse text, or scan a directory tree) that is
exercised here without touching real hardware, mirroring test_probes_parsing.py.
"""

from __future__ import annotations

import struct

import pytest

from cableprobe.config import Config
from cableprobe.models import (
    KIND_AUDIO_DEVICE,
    KIND_KERNEL_MODULE,
    KIND_KEYSTROKE_TIMING,
    KIND_LISTENING_SOCKET,
    KIND_MOUNT,
    KIND_NETWORK_CONFIG,
    KIND_PCI_DEVICE,
    KIND_SERIAL_DEVICE,
    KIND_USB_INTERFACE,
    KIND_USB_PD,
    KIND_USB_TOPOLOGY,
    KIND_VIDEO_DEVICE,
    KIND_WIFI_AP,
)
from cableprobe.probes import media_devices, serial_devices, system_state, usb_sysfs
from cableprobe.probes.keystroke_cadence import (
    parse_key_down_timestamps,
    summarise_cadence,
)
from cableprobe.probes.media_devices import (
    AudioDeviceProbe,
    VideoDeviceProbe,
    _video_from_udev,
    parse_asound_cards,
    scan_sysfs_v4l,
)
from cableprobe.probes.network_state import (
    _decode_le_ipv4,
    _decode_proc_net_address,
    annotate_with_ss,
    build_network_config_observations,
    parse_proc_net_route,
    parse_proc_net_tcp,
    parse_resolv_conf,
)
from cableprobe.probes.serial_devices import (
    SerialDeviceProbe,
    _observation_from_udev,
    scan_sysfs_tty,
)
from cableprobe.probes.system_state import (
    MountProbe,
    PciDeviceProbe,
    parse_proc_modules,
    parse_proc_mounts,
    scan_pci_sysfs,
)
from cableprobe.probes.usb_sysfs import (
    UsbDescriptorProbe,
    _class_name,
    _depth,
    _is_root_hub,
    descriptor_observations,
    scan_usb_sysfs,
    topology_observations,
)
from cableprobe.probes.usbc_pd import _role, scan_typec
from cableprobe.probes.wifi_scan import parse_iw_scan, parse_nmcli_wifi


_CFG = Config()


class FakeUdevDevice:
    """Minimal stand-in for a pyudev.Device: a property dict plus a few attrs."""

    def __init__(
        self, props: dict, *, sys_name="dev0", driver=None, parent=object(), usb_parent=None
    ):
        self._props = props
        self.sys_name = sys_name
        self.driver = driver
        self.parent = parent
        self._usb_parent = usb_parent

    def get(self, key, default=None):
        return self._props.get(key, default)

    def find_parent(self, subsystem, device_type=None):
        return self._usb_parent


# --------------------------------------------------------------------------
# helpers to build fake sysfs trees
# --------------------------------------------------------------------------


def _w(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(text), encoding="utf-8")


# --------------------------------------------------------------------------
# serial
# --------------------------------------------------------------------------


def test_scan_sysfs_tty_keeps_only_real_ports(tmp_path):
    tty = tmp_path / "tty"
    # virtual console: no "device" symlink -> ignored
    _w(tty / "tty0" / "dev", "4:0")
    # real USB serial port
    dev = tmp_path / "devices" / "usb1" / "1-1" / "1-1:1.0" / "ttyACM0"
    _w(dev / "uevent")
    (tty / "ttyACM0").mkdir(parents=True)
    (tty / "ttyACM0" / "device").symlink_to(dev)
    drv = tmp_path / "bus" / "usb-serial" / "drivers" / "cdc_acm"
    drv.mkdir(parents=True)
    (tty / "ttyACM0" / "device" / "driver").symlink_to(drv)

    out = scan_sysfs_tty(str(tty))
    assert [o.identity for o in out] == ["tty:ttyACM0"]
    acm = out[0]
    assert acm.kind == KIND_SERIAL_DEVICE
    assert acm.attributes["driver"] == "cdc_acm"
    assert acm.attributes["is_usb"] is True
    assert acm.attributes["usb_serial"] is True


# --------------------------------------------------------------------------
# audio / video
# --------------------------------------------------------------------------


ASOUND_SAMPLE = """\
 0 [Headphones     ]: bcm2835_headpho - bcm2835 Headphones
                      bcm2835 Headphones
 1 [C920           ]: USB-Audio - HD Pro Webcam C920
                      Logitech HD Pro Webcam C920 at usb-0000:01:00.0-1.4
"""


def test_parse_asound_cards():
    out = parse_asound_cards(ASOUND_SAMPLE)
    ids = {o.identity for o in out}
    assert ids == {"sound:Headphones", "sound:C920"}
    usb = next(o for o in out if o.identity == "sound:C920")
    assert usb.kind == KIND_AUDIO_DEVICE
    assert usb.attributes["is_usb"] is True
    assert usb.attributes["driver"] == "USB-Audio"
    onboard = next(o for o in out if o.identity == "sound:Headphones")
    assert onboard.attributes["is_usb"] is False


def test_scan_sysfs_v4l(tmp_path):
    v4l = tmp_path / "video4linux"
    _w(v4l / "video0" / "name", "HD Pro Webcam C920")
    real = tmp_path / "devices" / "usb1" / "1-1.4" / "1-1.4:1.0" / "video4linux" / "video0"
    real.mkdir(parents=True)
    (v4l / "video0" / "device").symlink_to(real.parent)

    out = scan_sysfs_v4l(str(v4l))
    assert len(out) == 1
    cam = out[0]
    assert cam.kind == KIND_VIDEO_DEVICE
    assert cam.identity == "v4l:video0"
    assert cam.attributes["human_name"] == "HD Pro Webcam C920"
    assert cam.attributes["is_usb"] is True


# --------------------------------------------------------------------------
# usb descriptors / topology
# --------------------------------------------------------------------------


def _fake_usb_tree(tmp_path):
    root = tmp_path / "usb_devices"
    # root hub
    for f, v in {"idVendor": "1d6b", "idProduct": "0002", "bDeviceClass": "09"}.items():
        _w(root / "usb1" / f, v)
    # external hub 1-1
    for f, v in {
        "idVendor": "05e3",
        "idProduct": "0608",
        "bDeviceClass": "09",
        "bNumInterfaces": "1",
        "maxchild": "4",
    }.items():
        _w(root / "1-1" / f, v)
    _w(root / "1-1" / "1-1:1.0" / "bInterfaceClass", "09")
    _w(root / "1-1" / "1-1:1.0" / "bInterfaceNumber", "00")
    _w(root / "1-1" / "1-1:1.0" / "bNumEndpoints", "1")
    # composite device 1-1.2 behind the hub: HID + vendor-specific
    for f, v in {
        "idVendor": "dead",
        "idProduct": "beef",
        "serial": "IMPLANT01",
        "bDeviceClass": "00",
        "bNumInterfaces": "2",
        "bMaxPower": "100mA",
    }.items():
        _w(root / "1-1.2" / f, v)
    _w(root / "1-1.2" / "1-1.2:1.0" / "bInterfaceClass", "03")
    _w(root / "1-1.2" / "1-1.2:1.0" / "bInterfaceNumber", "00")
    _w(root / "1-1.2" / "1-1.2:1.1" / "bInterfaceClass", "ff")
    _w(root / "1-1.2" / "1-1.2:1.1" / "bInterfaceNumber", "01")
    return root


def test_scan_usb_sysfs_shapes(tmp_path):
    devices = scan_usb_sysfs(str(_fake_usb_tree(tmp_path)))
    by_name = {d["sysname"]: d for d in devices}
    assert set(by_name) == {"usb1", "1-1", "1-1.2"}
    assert by_name["usb1"]["is_root_hub"] is True
    assert by_name["1-1"]["depth"] == 1
    assert by_name["1-1.2"]["depth"] == 2
    assert len(by_name["1-1.2"]["interfaces"]) == 2


def test_descriptor_observations_flag_interfaces(tmp_path):
    devices = scan_usb_sysfs(str(_fake_usb_tree(tmp_path)))
    obs = descriptor_observations(devices)
    kinds = {o.kind for o in obs}
    assert kinds == {KIND_USB_INTERFACE, "usb_descriptor"}
    # root hub interfaces are skipped
    assert not any("usb1" in o.identity for o in obs)
    hid = next(o for o in obs if o.identity == "usbif:dead:beef:IMPLANT01:00")
    assert hid.attributes["interface_class_name"] == "hid"
    assert sorted(hid.attributes["device_interface_classes"]) == ["hid", "vendor-specific"]
    desc = next(o for o in obs if o.identity == "usbdesc:dead:beef:IMPLANT01")
    assert desc.attributes["num_interfaces"] == "2"


def test_topology_observations_count_hubs(tmp_path):
    devices = scan_usb_sysfs(str(_fake_usb_tree(tmp_path)))
    obs = topology_observations(devices)
    summary = next(o for o in obs if o.identity == "usbtopology:summary")
    assert summary.kind == KIND_USB_TOPOLOGY
    assert summary.attributes["external_hub_count"] == 1
    assert summary.attributes["device_count"] == 2  # 1-1 and 1-1.2, not the root hub
    assert any(o.identity.startswith("usbhub:") for o in obs)


# --------------------------------------------------------------------------
# usb-c / power delivery
# --------------------------------------------------------------------------


def test_role_decode():
    assert _role("[host] device") == "host"
    assert _role("source [sink]") == "sink"
    assert _role("dfp") == "dfp"
    assert _role(None) is None


def test_scan_typec_port_and_partner(tmp_path):
    tc = tmp_path / "typec"
    _w(tc / "port0" / "data_role", "[host] device")
    _w(tc / "port0" / "power_role", "source [sink]")
    _w(tc / "port0" / "power_operation_mode", "usb_power_delivery")
    _w(tc / "port0" / "usb_power_delivery_revision", "3.0")
    # partner with a DisplayPort alt mode, active
    _w(tc / "port0-partner" / "supports_usb_power_delivery", "yes")
    _w(tc / "port0-partner" / "identity" / "product", "0x1234abcd")
    _w(tc / "port0-partner" / "port0-partner.0" / "svid", "ff01")
    _w(tc / "port0-partner" / "port0-partner.0" / "active", "yes")

    out = scan_typec(str(tc))
    ids = {o.identity for o in out}
    assert ids == {"typec:port0", "typec:port0-partner"}
    port = next(o for o in out if o.identity == "typec:port0")
    assert port.kind == KIND_USB_PD
    assert port.attributes["data_role"] == "host"
    assert port.attributes["power_role"] == "sink"
    assert port.attributes["partner_attached"] is True
    partner = next(o for o in out if o.identity == "typec:port0-partner")
    assert partner.attributes["alt_modes"] == ["port0-partner.0"]
    assert partner.attributes["alt_modes_active"] == ["port0-partner.0"]
    assert partner.attributes["product"] == "0x1234abcd"


def test_scan_typec_no_partner(tmp_path):
    tc = tmp_path / "typec"
    _w(tc / "port0" / "data_role", "[device]")
    out = scan_typec(str(tc))
    assert [o.identity for o in out] == ["typec:port0"]
    assert out[0].attributes["partner_attached"] is False


# --------------------------------------------------------------------------
# kernel modules / mounts / pci
# --------------------------------------------------------------------------


PROC_MODULES_SAMPLE = """\
cdc_ncm 45056 1 huawei_cdc_ncm, Live 0xffffffffc0a11000
usbnet 45056 1 cdc_ncm, Live 0xffffffffc0a00000
usbcore 335872 6 cdc_ncm,usbnet,usbhid,uas,usb_storage, Live 0xffffffffc09a0000
fuse 176128 0 - Live 0xffffffffc0800000
"""


def test_parse_proc_modules():
    out = parse_proc_modules(PROC_MODULES_SAMPLE)
    by_name = {o.attributes["name"]: o for o in out}
    assert set(by_name) == {"cdc_ncm", "usbnet", "usbcore", "fuse"}
    assert by_name["cdc_ncm"].kind == KIND_KERNEL_MODULE
    assert by_name["cdc_ncm"].identity == "kmod:cdc_ncm"
    assert by_name["cdc_ncm"].attributes["used_by"] == ["huawei_cdc_ncm"]
    assert by_name["cdc_ncm"].attributes["size"] == 45056
    assert by_name["fuse"].attributes["used_by"] == []


PROC_MOUNTS_SAMPLE = """\
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/mmcblk0p2 / ext4 rw,noatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev 0 0
/dev/sda1 /media/pi/CRUZER vfat rw,nosuid,nodev,relatime 0 0
"""


def test_parse_proc_mounts_keeps_devices_and_media():
    out = parse_proc_mounts(PROC_MOUNTS_SAMPLE)
    ids = {o.identity for o in out}
    assert ids == {"mount:/", "mount:/media/pi/CRUZER"}
    usb = next(o for o in out if o.identity == "mount:/media/pi/CRUZER")
    assert usb.kind == KIND_MOUNT
    assert usb.attributes["source"] == "/dev/sda1"
    assert usb.attributes["fstype"] == "vfat"
    assert usb.attributes["removable_path"] is True


def test_scan_pci_sysfs(tmp_path):
    pci = tmp_path / "pci"
    slot = pci / "0000:00:14.0"
    _w(slot / "vendor", "0x8086")
    _w(slot / "device", "0x9d2f")
    _w(slot / "class", "0x0c0330")
    drv = tmp_path / "drivers" / "xhci_hcd"
    drv.mkdir(parents=True)
    (slot / "driver").symlink_to(drv)

    tb = tmp_path / "thunderbolt"
    _w(tb / "0-1" / "device_name", "Rogue Dock")
    _w(tb / "0-1" / "authorized", "0")

    out = scan_pci_sysfs(str(pci), str(tb))
    ids = {o.identity for o in out}
    assert ids == {"pci:0000:00:14.0", "thunderbolt:0-1"}
    dev = next(o for o in out if o.identity == "pci:0000:00:14.0")
    assert dev.kind == KIND_PCI_DEVICE
    assert dev.attributes["vendor_id"] == "8086"
    assert dev.attributes["driver"] == "xhci_hcd"
    tbd = next(o for o in out if o.identity == "thunderbolt:0-1")
    assert tbd.attributes["authorized"] == "0"


# --------------------------------------------------------------------------
# routing / listeners
# --------------------------------------------------------------------------


def test_decode_le_ipv4():
    assert _decode_le_ipv4("0100A8C0") == "192.168.0.1"
    assert _decode_le_ipv4("00000000") == "0.0.0.0"


PROC_NET_ROUTE_SAMPLE = """\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
usb0\t00000000\t0100FEA9\t0003\t0\t0\t50\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""


def test_parse_proc_net_route_and_config():
    rows = parse_proc_net_route(PROC_NET_ROUTE_SAMPLE)
    assert len(rows) == 2  # only the two default routes
    obs = build_network_config_observations(rows, ["1.1.1.1", "8.8.8.8"])
    route = next(o for o in obs if o.identity == "route:default")
    assert route.kind == KIND_NETWORK_CONFIG
    # lowest metric (usb0, 50) wins as the effective default route
    assert route.attributes["interface"] == "usb0"
    dns = next(o for o in obs if o.identity == "dns:resolvers")
    assert dns.attributes["primary"] == "1.1.1.1"


def test_parse_resolv_conf():
    text = "search lan\nnameserver 192.168.1.1\nnameserver fe80::1\n# comment\n"
    assert parse_resolv_conf(text) == ["192.168.1.1", "fe80::1"]


PROC_NET_TCP_SAMPLE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 54321 1 0000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000 100 0 0 10 0
   2: 0100007F:8AE2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000 20 0 0 10 0
"""


def test_parse_proc_net_tcp_listeners_only():
    out = parse_proc_net_tcp(PROC_NET_TCP_SAMPLE)
    ids = {o.identity for o in out}
    assert ids == {"listen:tcp:127.0.0.1:8080", "listen:tcp:0.0.0.0:22"}
    ssh = next(o for o in out if o.identity == "listen:tcp:0.0.0.0:22")
    assert ssh.kind == KIND_LISTENING_SOCKET
    assert ssh.attributes["uid"] == 0


def test_annotate_with_ss():
    out = parse_proc_net_tcp(PROC_NET_TCP_SAMPLE)
    ss = 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=700,fd=3))\n'
    annotate_with_ss(out, ss)
    ssh = next(o for o in out if o.attributes["endpoint"] == "0.0.0.0:22")
    assert "sshd" in ssh.attributes["process"]


PROC_NET_TCP6_SAMPLE = """\
  sl  local_address                         remote_address                        st ... uid ... inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 700 1 0000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 800 1 0000 100 0 0 10 0
"""


def test_parse_proc_net_tcp6_ipv6_decode():
    out = parse_proc_net_tcp(PROC_NET_TCP6_SAMPLE, ipv6=True)
    ids = {o.identity for o in out}
    assert "listen:tcp6:[::]:80" in ids
    port80 = next(o for o in out if o.attributes["endpoint"] == "[::]:80")
    assert port80.attributes["protocol"] == "tcp6"


def test_decode_proc_net_address_edges():
    assert _decode_proc_net_address("0100007F:0016", ipv6=False) == ("127.0.0.1:22", 22)
    # malformed -> returned unchanged rather than raising
    assert _decode_proc_net_address("zzzz", ipv6=False) == ("zzzz", None)


PROC_NET_TCP_EPHEMERAL = """\
  sl  local_address rem_address   st ... uid ... inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100 1 0000 100 0 0 10 0
   1: 00000000:D2A9 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 200 1 0000 100 0 0 10 0
   2: 00000000:1F41 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 300 1 0000 100 0 0 10 0
"""


def test_parse_proc_net_tcp_drops_ephemeral_ports():
    # 0x0016=22 (kept), 0xD2A9=53929 (ephemeral, dropped), 0x1F41=8001 (kept)
    out = parse_proc_net_tcp(PROC_NET_TCP_EPHEMERAL)
    ports = sorted(o.attributes["port"] for o in out)
    assert ports == [22, 8001]
    # a custom lower bound still works
    out2 = parse_proc_net_tcp(PROC_NET_TCP_EPHEMERAL, ephemeral_min=8000)
    assert sorted(o.attributes["port"] for o in out2) == [22]


def test_ephemeral_port_min_reads_sysctl(tmp_path):
    from cableprobe.probes.network_state import DEFAULT_EPHEMERAL_MIN, ephemeral_port_min

    f = tmp_path / "range"
    f.write_text("40000\t60999\n", encoding="utf-8")
    assert ephemeral_port_min(str(f)) == 40000
    assert ephemeral_port_min(str(tmp_path / "missing")) == DEFAULT_EPHEMERAL_MIN


def test_process_probe_skips_kernel_threads():
    from cableprobe.probes.processes import _is_kernel_thread

    assert _is_kernel_thread(2, 0, "kthreadd") is True
    assert _is_kernel_thread(2125090, 2, "kworker/3:3-pm") is True
    assert _is_kernel_thread(999, 999, "kworker/u8:1") is True  # prefix fallback
    assert _is_kernel_thread(1234, 1, "sshd") is False
    assert _is_kernel_thread(1234, 1000, "python3") is False


def test_process_probe_filters_noise_and_own_children(monkeypatch):
    import os
    import time

    from cableprobe.probes.processes import ProcessProbe

    now = time.time()
    own = os.getpid()

    class P:
        def __init__(self, info):
            self.info = info

    procs = [
        P({"pid": 10, "name": "sleep", "ppid": 1, "create_time": now, "username": "root"}),
        P({"pid": 11, "name": "lsusb", "ppid": own, "create_time": now, "username": "root"}),
        P({"pid": 12, "name": "ModemManager", "ppid": 1, "create_time": now, "username": "root"}),
        P({"pid": 13, "name": "bash", "ppid": 1, "create_time": now - 9999, "username": "pi"}),
    ]
    monkeypatch.setattr(
        "cableprobe.probes.processes.psutil.process_iter", lambda fields: procs
    )
    out = ProcessProbe(_CFG, now - 1).snapshot()
    names = {o.attributes["name"] for o in out}
    assert names == {"ModemManager"}  # sleep / own child / pre-session dropped


def test_process_probe_redacts_secrets_in_cmdline(monkeypatch):
    import time

    from cableprobe.probes.processes import ProcessProbe

    now = time.time()

    class P:
        def __init__(self, info):
            self.info = info

    procs = [
        P(
            {
                "pid": 42,
                "name": "loader",
                "ppid": 1,
                "create_time": now,
                "username": "root",
                "cmdline": ["loader", "--token", "s3cr3tValueGoesHere", "--host", "h"],
            }
        )
    ]
    monkeypatch.setattr(
        "cableprobe.probes.processes.psutil.process_iter", lambda fields: procs
    )
    (obs,) = ProcessProbe(_CFG, now - 1).snapshot()
    assert "s3cr3tValueGoesHere" not in obs.attributes["cmdline"]
    assert "--token ***" in obs.attributes["cmdline"]
    assert "--host h" in obs.attributes["cmdline"]


def test_kernel_log_signal_keywords_exclude_routine_chatter():
    from cableprobe.probes.kernel_log import SIGNAL_KEYWORDS, VERBOSE_KEYWORDS

    assert "usb" not in SIGNAL_KEYWORDS
    assert "input" not in SIGNAL_KEYWORDS
    assert "hid" not in SIGNAL_KEYWORDS
    assert "cdc_ncm" in SIGNAL_KEYWORDS
    assert "unable to enumerate" in SIGNAL_KEYWORDS
    # verbose mode brings the chatter back
    assert "usb" in VERBOSE_KEYWORDS and "cdc_ncm" in VERBOSE_KEYWORDS


def test_input_probe_dedupes_event_char_nodes(monkeypatch):
    from cableprobe.probes import input_devices
    from cableprobe.probes.input_devices import InputDeviceProbe

    class FakeCtx:
        def list_devices(self, subsystem):
            return [
                FakeUdevDevice(
                    {
                        "NAME": '"USB Keyboard"',
                        "ID_INPUT": "1",
                        "ID_INPUT_KEYBOARD": "1",
                        "DEVPATH": "/d/input/input5",
                        "ID_BUS": "usb",
                    },
                    sys_name="input5",
                ),
                FakeUdevDevice(
                    {
                        "ID_MODEL": "USB_Keyboard",
                        "ID_INPUT": "1",
                        "ID_INPUT_KEYBOARD": "1",
                        "DEVPATH": "/d/input/input5/event4",
                        "DEVNAME": "/dev/input/event4",
                    },
                    sys_name="event4",
                ),
                FakeUdevDevice(
                    {"DEVPATH": "/d/input/input5/mouse0", "DEVNAME": "/dev/input/mouse0"},
                    sys_name="mouse0",
                ),
            ]

    monkeypatch.setattr(input_devices, "pyudev", object())
    monkeypatch.setattr(input_devices, "udev_context", lambda: FakeCtx())

    out = InputDeviceProbe(_CFG, 0.0).snapshot()
    assert [o.identity for o in out] == ["/d/input/input5"]
    assert out[0].attributes["ID_INPUT_KEYBOARD"] == "1"
    assert out[0].label == "input device: USB Keyboard"


def test_input_probe_merges_collections_of_one_usb_device(monkeypatch):
    from cableprobe.probes import input_devices
    from cableprobe.probes.input_devices import InputDeviceProbe

    usb = object()  # same parent object for all three collections

    class FakeCtx:
        def list_devices(self, subsystem):
            return [
                FakeUdevDevice(
                    {"NAME": '"USB Keyboard"', "ID_INPUT": "1",
                     "ID_INPUT_KEYBOARD": "1", "DEVPATH": "/d/input5", "ID_BUS": "usb"},
                    sys_name="input5", usb_parent=usb,
                ),
                FakeUdevDevice(
                    {"NAME": '"USB Keyboard Consumer Control"', "ID_INPUT": "1",
                     "DEVPATH": "/d/input6"},
                    sys_name="input6", usb_parent=usb,
                ),
                FakeUdevDevice(
                    {"NAME": '"USB Keyboard System Control"', "ID_INPUT": "1",
                     "DEVPATH": "/d/input7"},
                    sys_name="input7", usb_parent=usb,
                ),
            ]

    usb_dev = FakeUdevDevice({}, sys_name="1-1.2")
    monkeypatch.setattr(input_devices, "pyudev", object())
    monkeypatch.setattr(input_devices, "udev_context", lambda: FakeCtx())
    monkeypatch.setattr(
        input_devices, "_usb_parent_key", lambda d: "1-1.2" if d.get("ID_INPUT") else None
    )

    out = InputDeviceProbe(_CFG, 0.0).snapshot()
    assert len(out) == 1
    merged = out[0]
    assert merged.identity == "input:usb:1-1.2"
    assert merged.label == "input device: USB Keyboard"  # shortest name wins
    assert merged.attributes["ID_INPUT_KEYBOARD"] == "1"
    assert merged.attributes["collection_count"] == 3
    assert "USB Keyboard Consumer Control" in merged.attributes["collections"]


def test_decode_le_ipv4_bad_input_is_returned_unchanged():
    assert _decode_le_ipv4("not-hex") == "not-hex"


# --------------------------------------------------------------------------
# parser edge cases
# --------------------------------------------------------------------------


def test_parse_proc_modules_permanent_and_short_lines():
    text = (
        "ipv6 610304 28 [permanent], Live 0xffffffffc0400000\n"
        "brokenline\n"
        "\n"
        "spidev 20480 0 - Live 0xffffffffc02c0000\n"
    )
    out = parse_proc_modules(text)
    names = {o.attributes["name"] for o in out}
    assert names == {"ipv6", "spidev"}
    ipv6 = next(o for o in out if o.attributes["name"] == "ipv6")
    assert ipv6.attributes["used_by"] == ["[permanent]"]
    assert ipv6.attributes["refcount"] == 28


def test_parse_proc_mounts_escaped_spaces_and_short_lines():
    text = (
        "/dev/sda1 /media/pi/My\\040Disk vfat rw 0 0\n"
        "junk line here\n"
        "/dev/sda2 /mnt/x ext4 ro,noatime 0 0\n"
    )
    out = parse_proc_mounts(text)
    ids = {o.identity for o in out}
    assert ids == {"mount:/media/pi/My Disk", "mount:/mnt/x"}
    ro = next(o for o in out if o.identity == "mount:/mnt/x")
    assert ro.attributes["read_only"] is True


def test_scan_pci_sysfs_missing_files_and_no_driver(tmp_path):
    pci = tmp_path / "pci"
    slot = pci / "0000:00:00.0"
    slot.mkdir(parents=True)  # a slot dir with no vendor/device/class/driver
    out = scan_pci_sysfs(str(pci), str(tmp_path / "no-thunderbolt"))
    assert len(out) == 1
    assert out[0].identity == "pci:0000:00:00.0"
    assert out[0].attributes["driver"] is None
    assert out[0].attributes["vendor_id"] == ""


def test_usb_sysfs_small_helpers():
    assert _is_root_hub("usb1") is True
    assert _is_root_hub("1-1") is False
    assert _depth("usb1") == 0
    assert _depth("1-1") == 1
    assert _depth("1-1.4.2") == 3
    assert _class_name("3") == "hid"
    assert _class_name("09") == "hub"
    assert _class_name(None) is None
    assert _class_name("7a") == "7a"  # unknown code passes through


def test_scan_typec_port_alt_mode_and_inactive(tmp_path):
    tc = tmp_path / "typec"
    _w(tc / "port0" / "data_role", "[host]")
    # a port-level alt mode that is NOT active
    _w(tc / "port0" / "port0.0" / "svid", "ff01")
    _w(tc / "port0" / "port0.0" / "active", "no")
    out = scan_typec(str(tc))
    port = next(o for o in out if o.identity == "typec:port0")
    assert port.attributes["port_alt_modes"] == ["port0.0"]
    # port0.0 must not be mistaken for its own port
    assert "typec:port0.0" not in {o.identity for o in out}


# --------------------------------------------------------------------------
# Wi-Fi scan parsers
# --------------------------------------------------------------------------


IW_SCAN_SAMPLE = """\
BSS aa:bb:cc:dd:ee:ff(on wlan0) -- associated
\tfreq: 2437
\tsignal: -42.00 dBm
\tSSID: HomeNet
BSS 11:22:33:44:55:66(on wlan0)
\tfreq: 5180
\tsignal: -78.00 dBm
\tSSID: FarAway
BSS de:ad:be:ef:00:01(on wlan0)
\tfreq: 2412
\tsignal: -30.00 dBm
\tSSID:\x20
"""


def test_parse_iw_scan():
    out = parse_iw_scan(IW_SCAN_SAMPLE, interface="wlan0")
    by_bssid = {o.attributes["bssid"]: o for o in out}
    assert set(by_bssid) == {
        "aa:bb:cc:dd:ee:ff",
        "11:22:33:44:55:66",
        "de:ad:be:ef:00:01",
    }
    home = by_bssid["aa:bb:cc:dd:ee:ff"]
    assert home.kind == KIND_WIFI_AP
    assert home.attributes["ssid"] == "HomeNet"
    assert home.attributes["signal_dbm"] == -42.0
    assert home.attributes["channel"] == 6
    assert home.attributes["associated"] is True
    assert home.attributes["strong_signal"] is True

    far = by_bssid["11:22:33:44:55:66"]
    assert far.attributes["strong_signal"] is False
    assert far.attributes["channel"] == 36

    hidden = by_bssid["de:ad:be:ef:00:01"]
    assert hidden.attributes["ssid"] == "<hidden>"
    assert hidden.attributes["strong_signal"] is True  # -30 dBm, right next to the host


def test_parse_nmcli_wifi_escaped_bssid_and_signal():
    text = (
        r"AA\:BB\:CC\:DD\:EE\:FF:HomeNet:6:2437 MHz:88:*"
        + "\n"
        + r"11\:22\:33\:44\:55\:66:Neighbour:36:5180 MHz:30:"
        + "\n"
    )
    out = parse_nmcli_wifi(text, interface="wlan0")
    by_bssid = {o.attributes["bssid"]: o for o in out}
    home = by_bssid["aa:bb:cc:dd:ee:ff"]
    assert home.attributes["ssid"] == "HomeNet"
    assert home.attributes["channel"] == 6
    assert home.attributes["associated"] is True
    # quality 88 -> ~ -56 dBm ; quality 30 -> -85 dBm
    assert home.attributes["signal_dbm"] == -56.0
    assert by_bssid["11:22:33:44:55:66"].attributes["strong_signal"] is False


# --------------------------------------------------------------------------
# keystroke cadence
# --------------------------------------------------------------------------


def _input_event_bytes(events: list[tuple[float, int, int, int]]) -> bytes:
    """events: (timestamp_seconds, type, code, value)."""

    fmt = "llHHi"
    out = b""
    for ts, etype, code, value in events:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        out += struct.pack(fmt, sec, usec, etype, code, value)
    return out


def test_parse_key_down_timestamps_filters_type_and_value():
    raw = _input_event_bytes(
        [
            (10.000, 1, 30, 1),  # EV_KEY 'a' press   -> kept
            (10.010, 1, 30, 0),  # release            -> dropped (value 0)
            (10.020, 1, 30, 2),  # autorepeat         -> dropped (value 2)
            (10.030, 2, 0, 5),   # EV_REL             -> dropped (type != EV_KEY)
            (10.040, 1, 31, 1),  # EV_KEY 's' press   -> kept
        ]
    )
    stamps = parse_key_down_timestamps(raw)
    assert stamps == pytest.approx([10.000, 10.040])


def test_summarise_cadence_flags_superhuman():
    # 40 keys, 5 ms apart -> 200 keys/s
    ts = [i * 0.005 for i in range(40)]
    s = summarise_cadence(ts)
    assert s["keystrokes"] == 40
    assert s["superhuman_speed"] is True
    assert s["looks_injected"] is True


def test_summarise_cadence_flags_robotic_regularity():
    # 30 keys exactly 100 ms apart: not superhuman, but machine-regular
    ts = [i * 0.100 for i in range(30)]
    s = summarise_cadence(ts)
    assert s["superhuman_speed"] is False
    assert s["robotically_regular"] is True
    assert s["looks_injected"] is True


def test_summarise_cadence_human_typing_is_not_flagged():
    import random

    rng = random.Random(1)
    t = 0.0
    ts = []
    for _ in range(40):
        t += rng.uniform(0.08, 0.30)  # 3-12 keys/s, irregular
        ts.append(t)
    s = summarise_cadence(ts)
    assert s["looks_injected"] is False


def test_summarise_cadence_too_few_keys():
    assert summarise_cadence([1.0]) == {
        "keystrokes": 1,
        "superhuman_speed": False,
        "robotically_regular": False,
        "looks_injected": False,
    }


# --------------------------------------------------------------------------
# probe .snapshot() / .availability() dispatch (the sysfs-fallback path;
# pyudev is not importable in the test environment so it is always taken)
# --------------------------------------------------------------------------


def test_serial_probe_snapshot_via_sysfs(tmp_path, monkeypatch):
    tty = tmp_path / "tty"
    dev = tmp_path / "d" / "usb1" / "1-1" / "1-1:1.0" / "ttyUSB0"
    dev.mkdir(parents=True)
    (tty / "ttyUSB0").mkdir(parents=True)
    (tty / "ttyUSB0" / "device").symlink_to(dev)
    monkeypatch.setattr(serial_devices, "SYS_CLASS_TTY", str(tty))
    monkeypatch.setattr(serial_devices, "pyudev", None)

    probe = SerialDeviceProbe(_CFG, 0.0)
    assert probe.availability().ok is True
    out = probe.snapshot()
    assert [o.identity for o in out] == ["tty:ttyUSB0"]


def test_mount_probe_snapshot(tmp_path, monkeypatch):
    mounts = tmp_path / "mounts"
    mounts.write_text("/dev/sda1 /media/x vfat rw 0 0\n", encoding="utf-8")
    monkeypatch.setattr(system_state, "PROC_MOUNTS", str(mounts))
    probe = MountProbe(_CFG, 0.0)
    assert probe.availability().ok is True
    assert [o.identity for o in probe.snapshot()] == ["mount:/media/x"]


def test_pci_probe_unavailable_without_buses(monkeypatch):
    monkeypatch.setattr(system_state, "SYS_BUS_PCI", "/no/such/pci")
    monkeypatch.setattr(system_state, "SYS_BUS_THUNDERBOLT", "/no/such/tb")
    assert PciDeviceProbe(_CFG, 0.0).availability().ok is False


def test_usb_descriptor_probe_snapshot(tmp_path, monkeypatch):
    root = _fake_usb_tree(tmp_path)
    monkeypatch.setattr(usb_sysfs, "SYS_BUS_USB_DEVICES", str(root))
    probe = UsbDescriptorProbe(_CFG, 0.0)
    assert probe.availability().ok is True
    out = probe.snapshot()
    assert any(o.attributes.get("interface_class_name") == "hid" for o in out)


def test_video_probe_snapshot_via_sysfs(tmp_path, monkeypatch):
    v4l = tmp_path / "v4l"
    _w(v4l / "video0" / "name", "Fake Cam")
    monkeypatch.setattr(media_devices, "SYS_CLASS_V4L", str(v4l))
    monkeypatch.setattr(media_devices, "pyudev", None)
    probe = VideoDeviceProbe(_CFG, 0.0)
    assert probe.availability().ok is True
    assert [o.identity for o in probe.snapshot()] == ["v4l:video0"]


def test_audio_probe_snapshot_via_proc(tmp_path, monkeypatch):
    cards = tmp_path / "cards"
    cards.write_text(ASOUND_SAMPLE, encoding="utf-8")
    monkeypatch.setattr(media_devices, "PROC_ASOUND_CARDS", str(cards))
    monkeypatch.setattr(media_devices, "pyudev", None)
    probe = AudioDeviceProbe(_CFG, 0.0)
    assert probe.availability().ok is True
    assert {o.identity for o in probe.snapshot()} == {"sound:Headphones", "sound:C920"}


# --------------------------------------------------------------------------
# pyudev-branch helpers, exercised with a fake device object
# --------------------------------------------------------------------------


def test_serial_observation_from_udev():
    dev = FakeUdevDevice(
        {
            "DEVNAME": "/dev/ttyACM0",
            "ID_USB_DRIVER": "cdc_acm",
            "ID_BUS": "usb",
            "ID_VENDOR_ID": "1234",
            "ID_MODEL_ID": "5678",
            "ID_SERIAL_SHORT": "ABC",
        },
        sys_name="ttyACM0",
    )
    obs = _observation_from_udev(dev)
    assert obs.identity == "tty:ttyACM0"
    assert obs.attributes["usb_serial"] is True
    assert obs.attributes["is_usb"] is True
    assert obs.attributes["serial"] == "ABC"


def test_video_observation_from_udev():
    dev = FakeUdevDevice(
        {
            "DEVNAME": "/dev/video0",
            "ID_V4L_PRODUCT": "Evil Cam",
            "ID_BUS": "usb",
            "ID_VENDOR_ID": "dead",
            "ID_MODEL_ID": "beef",
        },
        sys_name="video0",
    )
    obs = _video_from_udev(dev)
    assert obs.identity == "v4l:video0"
    assert obs.attributes["human_name"] == "Evil Cam"
    assert obs.attributes["is_usb"] is True


def test_audio_from_udev_skips_non_card_nodes():
    from cableprobe.probes.media_devices import _audio_from_udev

    assert _audio_from_udev(FakeUdevDevice({}, sys_name="controlC0")) is None
    card = _audio_from_udev(
        FakeUdevDevice(
            {"ID_BUS": "usb", "ID_MODEL": "USB Mic"}, sys_name="card1"
        )
    )
    assert card is not None and card.identity == "sound:card1"
    assert card.attributes["is_usb"] is True


# --------------------------------------------------------------------------
# wifi_scan / keystroke_cadence probe classes
# --------------------------------------------------------------------------


def test_udev_event_is_interesting_filters_kernel_internal_subsystems():
    from cableprobe.probes.udev_monitor import event_is_interesting

    assert event_is_interesting("usb", "usb_device") is True
    assert event_is_interesting("block", "disk") is True
    assert event_is_interesting("net", None) is True
    # the swarm a USB disk brings up
    for s in ("scsi_device", "scsi_disk", "scsi_generic", "bsg", "bdi"):
        assert event_is_interesting(s, None) is False
    # block partitions are covered by their parent disk
    assert event_is_interesting("block", "partition") is False


def test_oui_family_groups_locally_administered_bssids():
    from cableprobe.probes.wifi_scan import oui_family

    assert oui_family("bc:30:d9:85:dc:eb") == oui_family("be:30:d9:a5:dc:ec")
    assert oui_family("cc:d4:2e:17:ed:cf") == oui_family("ce:d4:2e:27:ed:de")
    assert oui_family("bc:30:d9:00:00:00") != oui_family("cc:d4:2e:00:00:00")
    assert oui_family("garbage") == "garbage"


def test_wifi_scan_probe_snapshot_uses_iw(monkeypatch):
    from cableprobe.probes import wifi_scan

    monkeypatch.setattr(wifi_scan, "wifi_interfaces", lambda root=None: ["wlan0"])
    monkeypatch.setattr(wifi_scan, "have_tool", lambda name: name == "iw")
    monkeypatch.setattr(
        wifi_scan, "run_command", lambda *a, **k: (0, IW_SCAN_SAMPLE, "")
    )
    probe = wifi_scan.WifiScanProbe(_CFG, 0.0)
    assert probe.availability().ok is True

    first = probe.snapshot()
    assert {o.kind for o in first} == {KIND_WIFI_AP}
    assert all(o.attributes["family_new_this_session"] for o in first)

    # a later scan: the same APs are no longer "new this session"
    second = probe.snapshot()
    assert not any(o.attributes["family_new_this_session"] for o in second)


def test_wifi_scan_probe_unavailable_without_interface(monkeypatch):
    from cableprobe.probes import wifi_scan

    monkeypatch.setattr(wifi_scan, "have_tool", lambda name: True)
    monkeypatch.setattr(wifi_scan, "wifi_interfaces", lambda root=None: [])
    assert wifi_scan.WifiScanProbe(_CFG, 0.0).availability().ok is False


def test_read_sysfs_shared_helper(tmp_path):
    from cableprobe.probes.base import read_sysfs

    f = tmp_path / "attr"
    f.write_text("  0x1d6b \n")
    assert read_sysfs(f) == "0x1d6b"
    assert read_sysfs(tmp_path / "missing") is None
    assert read_sysfs(tmp_path / "missing", default="") == ""
    (tmp_path / "empty").write_text("   \n")
    assert read_sysfs(tmp_path / "empty") is None


def test_probe_modules_use_the_shared_read_sysfs():
    # E2: usb_sysfs / usbc_pd / system_state / hid_report no longer carry their
    # own copy of the sysfs reader.
    import cableprobe.probes.base as base
    from cableprobe.probes import hid_report, system_state, usb_sysfs, usbc_pd

    for mod in (usb_sysfs, usbc_pd, system_state, hid_report):
        assert mod.read_sysfs is base.read_sysfs
        assert not hasattr(mod, "_read")
        assert not hasattr(mod, "_read_text")


def test_keystroke_probe_disabled_by_config():
    cfg = Config.model_validate({"probes": {"capture_keystroke_timing": False}})
    from cableprobe.probes.keystroke_cadence import KeystrokeCadenceProbe

    probe = KeystrokeCadenceProbe(cfg, 0.0)
    a = probe.availability()
    assert a.ok is False and "disabled" in a.detail


def test_keystroke_probe_snapshot_from_collected_timestamps():
    from cableprobe.probes.keystroke_cadence import KeystrokeCadenceProbe

    probe = KeystrokeCadenceProbe(_CFG, 0.0)
    with probe._lock:
        probe._timestamps["event3"] = [i * 0.004 for i in range(50)]  # ~250 keys/s
    out = probe.snapshot()
    assert len(out) == 1
    assert out[0].kind == KIND_KEYSTROKE_TIMING
    assert out[0].identity == "kbdtiming:event3"
    assert out[0].attributes["looks_injected"] is True
