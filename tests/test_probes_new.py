# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Parser / scanner tests for the probes added after v0.1.

Every probe keeps a pure function (parse text, or scan a directory tree) that is
exercised here without touching real hardware, mirroring test_probes_parsing.py.
"""

from __future__ import annotations

from cableprobe.models import (
    KIND_AUDIO_DEVICE,
    KIND_KERNEL_MODULE,
    KIND_LISTENING_SOCKET,
    KIND_MOUNT,
    KIND_NETWORK_CONFIG,
    KIND_PCI_DEVICE,
    KIND_SERIAL_DEVICE,
    KIND_USB_INTERFACE,
    KIND_USB_PD,
    KIND_USB_TOPOLOGY,
    KIND_VIDEO_DEVICE,
)
from cableprobe.probes.media_devices import parse_asound_cards, scan_sysfs_v4l
from cableprobe.probes.network_state import (
    _decode_le_ipv4,
    annotate_with_ss,
    build_network_config_observations,
    parse_proc_net_route,
    parse_proc_net_tcp,
    parse_resolv_conf,
)
from cableprobe.probes.serial_devices import scan_sysfs_tty
from cableprobe.probes.system_state import (
    parse_proc_modules,
    parse_proc_mounts,
    scan_pci_sysfs,
)
from cableprobe.probes.usb_sysfs import (
    descriptor_observations,
    scan_usb_sysfs,
    topology_observations,
)
from cableprobe.probes.usbc_pd import _role, scan_typec


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
    assert kinds == {KIND_USB_INTERFACE}
    # root hub interfaces are skipped
    assert not any("usb1" in o.identity for o in obs)
    hid = next(o for o in obs if o.identity == "usbif:dead:beef:IMPLANT01:00")
    assert hid.attributes["interface_class_name"] == "hid"
    assert sorted(hid.attributes["device_interface_classes"]) == ["hid", "vendor-specific"]


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
