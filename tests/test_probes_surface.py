# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""hid_report / persistence / connections probes."""

from __future__ import annotations

from cableprobe.models import (
    KIND_CONNECTION_FREQUENCY,
    KIND_HID_REPORT,
    KIND_OUTBOUND_CONNECTION,
    KIND_PERSISTENCE_ITEM,
)
from cableprobe.probes.connections import active_remotes, parse_outbound
from cableprobe.probes.hid_report import parse_hid_report_descriptor, scan_hid_reports
from cableprobe.probes.persistence import scan_persistence


# --------------------------------------------------------------------------
# hid_report
# --------------------------------------------------------------------------

# A minimal boot keyboard report descriptor (Usage Page Generic Desktop,
# Usage Keyboard, Collection ...). Enough bytes for the parser.
_KEYBOARD_RDESC = bytes(
    [
        0x05, 0x01,  # Usage Page (Generic Desktop)
        0x09, 0x06,  # Usage (Keyboard)
        0xA1, 0x01,  # Collection (Application)
        0x05, 0x07,  # Usage Page (Keyboard)
        0x81, 0x02,  # Input (Data,Var,Abs)
        0xC0,        # End Collection
    ]
)

_MOUSE_RDESC = bytes(
    [
        0x05, 0x01,  # Usage Page (Generic Desktop)
        0x09, 0x02,  # Usage (Mouse)
        0xA1, 0x01,  # Collection (Application)
        0x09, 0x01,  # Usage (Pointer)
        0x05, 0x09,  # Usage Page (Button)
        0x81, 0x02,  # Input
        0xC0,
    ]
)

_VENDOR_KBD_RDESC = _KEYBOARD_RDESC + bytes([0x06, 0x00, 0xFF, 0x09, 0x01, 0x81, 0x02])


def test_parse_keyboard_descriptor():
    s = parse_hid_report_descriptor(_KEYBOARD_RDESC)
    assert s["has_keyboard_usage"] is True
    assert s["has_pointer_usage"] is False
    assert s["has_vendor_usage_page"] is False


def test_parse_mouse_descriptor():
    s = parse_hid_report_descriptor(_MOUSE_RDESC)
    assert s["has_keyboard_usage"] is False
    assert s["has_pointer_usage"] is True


def test_parse_vendor_page_with_keyboard():
    s = parse_hid_report_descriptor(_VENDOR_KBD_RDESC)
    assert s["has_keyboard_usage"] is True
    assert s["has_vendor_usage_page"] is True
    assert "0xff00" in s["vendor_usage_pages"]


def test_parse_hid_report_descriptor_no_long_items_by_default():
    s = parse_hid_report_descriptor(_KEYBOARD_RDESC)
    assert s["has_long_items"] is False
    assert s["long_item_count"] == 0


def test_parse_hid_report_descriptor_resyncs_after_a_long_item():
    """The HID spec reserves prefix 0xFE to mean "long item, not short item":
    a 1-byte data length, a 1-byte long item tag, then that many bytes of
    data - a completely different layout from a short item's bSize/bType/
    bTag prefix. Misreading it as a short item (the old behaviour) desyncs
    every item after it - the item boundary lands mid-stream instead of at
    the start of the next real item. Chosen deliberately large enough that a
    parser which merely consumed 2 "value" bytes per short-item's own size
    field, instead of the declared long-item length, cannot land back on the
    real Usage Page by coincidence."""

    long_item = bytes([0xFE, 10, 0x00]) + bytes(10)  # data_size=10, tag=0, 10 bytes payload
    descriptor = long_item + _KEYBOARD_RDESC  # a real, unambiguous keyboard usage right after it

    s = parse_hid_report_descriptor(descriptor)
    assert s["has_long_items"] is True
    assert s["long_item_count"] == 1
    assert s["has_keyboard_usage"] is True  # the real item after it was still found


def test_parse_hid_report_descriptor_multiple_long_items():
    long_item = bytes([0xFE, 2, 0x00, 0xAA, 0xBB])
    descriptor = long_item + long_item + _MOUSE_RDESC
    s = parse_hid_report_descriptor(descriptor)
    assert s["long_item_count"] == 2
    assert s["has_pointer_usage"] is True


def test_parse_hid_report_descriptor_truncated_long_item_header_does_not_crash():
    # just the long-item prefix, no data-size byte at all
    s = parse_hid_report_descriptor(bytes([0xFE]))
    assert s["long_item_count"] == 1
    assert s["has_keyboard_usage"] is False


def test_parse_hid_report_descriptor_long_item_declaring_more_data_than_present():
    # data_size says 50 bytes follow; only a couple actually do. Must not
    # crash or attempt to index past the end - the arithmetic-only advance
    # naturally stops at the next while-loop bounds check.
    s = parse_hid_report_descriptor(bytes([0xFE, 50, 0x00, 0x01, 0x02]))
    assert s["long_item_count"] == 1


def test_scan_hid_reports_flags_unlabelled_keyboard(tmp_path):
    d = tmp_path / "0003:04F2:0939.0005"
    d.mkdir()
    (d / "report_descriptor").write_bytes(_KEYBOARD_RDESC)
    (d / "name").write_text("PixArt USB Optical Mouse", encoding="utf-8")

    out = scan_hid_reports(str(tmp_path))
    assert len(out) == 1
    o = out[0]
    assert o.kind == KIND_HID_REPORT
    assert o.attributes["declared"] == "pointer"
    assert o.attributes["keyboard_capable_but_not_labelled"] is True
    assert o.attributes["vendor_id"] == "04f2"


def test_scan_hid_reports_ok_for_real_keyboard(tmp_path):
    d = tmp_path / "0003:046D:C31C.0001"
    d.mkdir()
    (d / "report_descriptor").write_bytes(_KEYBOARD_RDESC)
    (d / "name").write_text("Logitech USB Keyboard", encoding="utf-8")
    (o,) = scan_hid_reports(str(tmp_path))
    assert o.attributes["keyboard_capable_but_not_labelled"] is False


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------


def test_scan_persistence_hashes_targets(tmp_path):
    rules = tmp_path / "udev"
    rules.mkdir()
    (rules / "99-evil.rules").write_text('ACTION=="add", RUN+="/tmp/x"\n', encoding="utf-8")
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    out = scan_persistence(
        targets=[("udev-rule", str(rules / "*.rules")), ("hosts", str(hosts))],
        home_roots=(),
    )
    ids = {o.identity for o in out}
    assert f"persist:{rules / '99-evil.rules'}" in ids
    item = next(o for o in out if o.identity.endswith("99-evil.rules"))
    assert item.kind == KIND_PERSISTENCE_ITEM
    digest = item.attributes["sha256"]
    assert len(digest) == 64 and item.attributes["present"] is True  # full sha256
    assert item.attributes["mode"] and item.attributes["uid"] is not None

    assert item.attributes["regular_file"] is True
    assert item.attributes["hash_truncated"] is False

    # a byte change moves the hash -> a delta later
    before = item.attributes["sha256"]
    (rules / "99-evil.rules").write_text("changed\n", encoding="utf-8")
    after = next(
        o
        for o in scan_persistence(
            targets=[("udev-rule", str(rules / "*.rules"))], home_roots=()
        )
    ).attributes["sha256"]
    assert before != after


def test_scan_persistence_detects_a_permission_only_change(tmp_path):
    import os

    f = tmp_path / "hardening.rules"
    f.write_text("ACTION==\"add\"\n")
    os.chmod(f, 0o644)
    before = scan_persistence(targets=[("udev-rule", str(f))], home_roots=())[0]
    os.chmod(f, 0o646)  # made world-writable, same bytes
    after = scan_persistence(targets=[("udev-rule", str(f))], home_roots=())[0]

    assert before.attributes["sha256"] == after.attributes["sha256"]
    assert before.attributes["mode"] != after.attributes["mode"]
    assert after.attributes["world_writable"] is True


def test_scan_persistence_marks_an_unreadable_file_incomplete(tmp_path, monkeypatch):
    import cableprobe.probes.persistence as mod

    f = tmp_path / "hosts"
    f.write_text("data")
    real_open = mod.os.open

    def _deny(path, *a, **k):
        if str(path) == str(f):
            raise PermissionError(13, "denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr(mod.os, "open", _deny)
    (item,) = scan_persistence(targets=[("hosts", str(f))], home_roots=())
    assert item.attributes["present"] is True  # not mistaken for absent
    assert item.attributes["sha256"] is None
    assert item.attributes["fingerprint_incomplete"] is True


def test_scan_persistence_does_not_hang_on_a_fifo_authorized_keys(tmp_path):
    import os

    # a local user plants a FIFO at ~/.ssh/authorized_keys; read() would block
    home = tmp_path / "mallory"
    (home / ".ssh").mkdir(parents=True)
    os.mkfifo(home / ".ssh" / "authorized_keys")

    out = scan_persistence(targets=[], home_roots=(str(tmp_path),))
    item = next(o for o in out if o.identity.endswith("authorized_keys"))
    assert item.attributes["present"] is True
    assert item.attributes["regular_file"] is False
    assert item.attributes["sha256"] is None


def test_scan_persistence_caps_a_huge_file(tmp_path, monkeypatch):
    import cableprobe.probes.persistence as mod

    monkeypatch.setattr(mod, "_MAX_HASH_BYTES", 64)
    big = tmp_path / "hosts"
    big.write_bytes(b"x" * 4096)
    (item,) = scan_persistence(targets=[("hosts", str(big))], home_roots=())
    assert item.attributes["hash_truncated"] is True
    assert item.attributes["fingerprint_incomplete"] is True
    assert len(item.attributes["sha256"]) == 64  # still a valid digest (of the prefix)


def test_scan_persistence_monitors_a_symlinked_regular_target(tmp_path):
    real = tmp_path / "real_keys"
    real.write_text("ssh-ed25519 AAAA...\n")
    link = tmp_path / "authorized_keys"
    link.symlink_to(real)
    (item,) = scan_persistence(targets=[("keys", str(link))], home_roots=())
    assert item.attributes["present"] is True
    assert item.attributes["regular_file"] is True
    assert item.attributes["symlink_target"] == str(real)
    before = item.attributes["sha256"]
    assert before and len(before) == 64

    real.write_text("ssh-ed25519 EVIL...\n")  # target rewritten -> the hash moves
    (item2,) = scan_persistence(targets=[("keys", str(link))], home_roots=())
    assert item2.attributes["sha256"] != before


def test_scan_persistence_finds_a_direct_fifo_at_a_fixed_target(tmp_path):
    # a fixed (non-glob) target, e.g. /etc/ld.so.preload, replaced with a FIFO
    import os

    fifo = tmp_path / "ld.so.preload"
    os.mkfifo(fifo)
    (item,) = scan_persistence(targets=[("ld.so.preload", str(fifo))], home_roots=())
    assert item.attributes["present"] is True
    assert item.attributes["regular_file"] is False
    assert item.attributes["sha256"] is None
    assert item.attributes["fingerprint_incomplete"] is True


def test_scan_persistence_finds_a_globbed_fifo(tmp_path):
    import os

    d = tmp_path / "cron.d"
    d.mkdir()
    os.mkfifo(d / "evil")
    (item,) = scan_persistence(targets=[("cron.d", str(d / "*"))], home_roots=())
    assert item.attributes["regular_file"] is False
    assert item.attributes["fingerprint_incomplete"] is True


def test_scan_persistence_finds_a_broken_symlink_at_a_fixed_target(tmp_path):
    link = tmp_path / "hosts"
    link.symlink_to(tmp_path / "does-not-exist")
    (item,) = scan_persistence(targets=[("hosts", str(link))], home_roots=())
    assert item.attributes["present"] is True  # the link itself exists
    assert item.attributes["sha256"] is None
    assert item.attributes["fingerprint_incomplete"] is True


def test_scan_persistence_finds_a_broken_symlink_at_a_globbed_target(tmp_path):
    d = tmp_path / "cron.d"
    d.mkdir()
    (d / "dangling").symlink_to(d / "nope")
    (item,) = scan_persistence(targets=[("cron.d", str(d / "*"))], home_roots=())
    assert item.attributes["fingerprint_incomplete"] is True


def test_scan_persistence_finds_a_broken_symlink_authorized_keys(tmp_path):
    home = tmp_path / "mallory"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").symlink_to(home / ".ssh" / "nope")

    out = scan_persistence(targets=[], home_roots=(str(tmp_path),))
    item = next(o for o in out if o.identity.endswith("authorized_keys"))
    assert item.attributes["present"] is True
    assert item.attributes["sha256"] is None
    assert item.attributes["fingerprint_incomplete"] is True


def test_scan_persistence_skips_a_bare_directory_glob_match(tmp_path):
    # a glob routinely matches an ordinary subdirectory - not itself suspicious
    d = tmp_path / "profile.d"
    d.mkdir()
    (d / "subdir").mkdir()
    out = scan_persistence(targets=[("profile.d", str(d / "*"))], home_roots=())
    assert out == []


def test_scan_persistence_absent_optional_target_produces_nothing(tmp_path):
    out = scan_persistence(
        targets=[("rc.local", str(tmp_path / "does-not-exist"))], home_roots=()
    )
    assert out == []
    # and a glob matching nothing at all is equally quiet
    out2 = scan_persistence(targets=[("cron.d", str(tmp_path / "empty" / "*"))], home_roots=())
    assert out2 == []


def test_scan_persistence_does_not_hang_on_a_symlink_to_a_fifo(tmp_path):
    import os

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    home = tmp_path / "u"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").symlink_to(fifo)

    out = scan_persistence(targets=[], home_roots=(str(tmp_path),))
    item = next(o for o in out if o.identity.endswith("authorized_keys"))
    assert item.attributes["regular_file"] is False
    assert item.attributes["sha256"] is None
    assert item.attributes["fingerprint_incomplete"] is True


# --------------------------------------------------------------------------
# connections
# --------------------------------------------------------------------------

_PROC_NET_TCP = """\
  sl  local_address rem_address   st ... uid ... inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 1 0000
   1: 0100007F:8AE2 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000 0 2 0000
   2: 0100007F:9002 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000 0 3 0000
   3: 0A00020F:C1B4 22D8B85D:01BB 02 00000000:00000000 00:00000000 00000000     0 0 4 0000
"""


def _hex_addr(ip: str, port: int) -> str:
    """``"10.0.1.2", 443`` -> the ``AABBCCDD:PPPP`` hex form
    ``/proc/net/tcp{,6}`` uses (little-endian 32-bit address, hex port)."""

    import socket
    import struct

    as_int = struct.unpack("<L", socket.inet_aton(ip))[0]
    return f"{as_int:08X}:{port:04X}"


def _synthetic_proc_net_tcp(remotes: list[str], *, port: int = 443) -> str:
    """A well-formed ``/proc/net/tcp`` table with one ESTABLISHED row per
    entry in ``remotes`` (IPs may repeat - each row is still a distinct
    connection, e.g. a different local port each time)."""

    lines = ["  sl  local_address rem_address   st ... uid ... inode"]
    for i, ip in enumerate(remotes):
        local_port = 1024 + (i % 60000)
        lines.append(
            f"{i:4d}: 0100007F:{local_port:04X} {_hex_addr(ip, port)} 01 "
            f"00000000:00000000 00:00000000 00000000  1000 0 {i} 0000"
        )
    return "\n".join(lines) + "\n"


def test_parse_outbound_keeps_only_routable_active():
    out = parse_outbound(_PROC_NET_TCP)
    remotes = sorted(o.attributes["remote"] for o in out)
    # 8.8.8.8:443 (established) and 93.184.216.34:443 (syn_sent) kept;
    # the LISTEN socket and the loopback->loopback connection dropped
    assert remotes == ["8.8.8.8:443", "93.184.216.34:443"]
    assert all(o.kind == KIND_OUTBOUND_CONNECTION for o in out)


def test_active_remotes_matches_the_routable_set_parse_outbound_uses():
    assert active_remotes(_PROC_NET_TCP) == {
        ("tcp", "8.8.8.8:443"),
        ("tcp", "93.184.216.34:443"),
    }


def test_accumulate_caps_new_keys_but_keeps_bumping_existing_ones():
    from cableprobe.probes.connections import _accumulate

    counts: dict = {}
    assert _accumulate(counts, {("tcp", "1.1.1.1:443")}, cap=2) is False
    assert _accumulate(counts, {("tcp", "2.2.2.2:443")}, cap=2) is False
    assert counts == {("tcp", "1.1.1.1:443"): 1, ("tcp", "2.2.2.2:443"): 1}

    # cap reached: a brand-new key is refused...
    hit = _accumulate(counts, {("tcp", "3.3.3.3:443")}, cap=2)
    assert hit is True
    assert ("tcp", "3.3.3.3:443") not in counts

    # ...but an already-tracked key - the one that matters for "repeated" -
    # keeps accumulating past the cap
    hit2 = _accumulate(counts, {("tcp", "1.1.1.1:443")}, cap=2)
    assert hit2 is False
    assert counts[("tcp", "1.1.1.1:443")] == 2


def test_connection_probe_emits_frequency_observations(tmp_path, monkeypatch):
    from cableprobe.config import Config
    from cableprobe.probes import connections as conn_mod
    from cableprobe.probes.connections import ConnectionProbe

    tcp = tmp_path / "tcp"
    tcp.write_text(_PROC_NET_TCP, encoding="utf-8")
    tcp6 = tmp_path / "tcp6"
    tcp6.write_text("", encoding="utf-8")
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP", str(tcp))
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP6", str(tcp6))

    probe = ConnectionProbe(Config(), 0.0)
    for _ in range(probe._repeat_threshold):
        probe._sample_once()

    freq = {
        o.attributes["remote"]: o
        for o in probe.snapshot()
        if o.kind == KIND_CONNECTION_FREQUENCY
    }
    assert freq["8.8.8.8:443"].attributes["seen_count"] == probe._repeat_threshold
    assert freq["8.8.8.8:443"].attributes["sample_count"] == probe._repeat_threshold
    assert freq["8.8.8.8:443"].attributes["repeated"] is True

    # a second snapshot with nothing sampled in between emits no frequency obs
    assert all(o.kind != KIND_CONNECTION_FREQUENCY for o in probe.snapshot())


def test_connection_probe_overflow_is_visible_as_incomplete_monitoring(tmp_path, monkeypatch):
    from cableprobe.config import Config
    from cableprobe.probes import connections as conn_mod
    from cableprobe.probes.connections import ConnectionProbe

    tcp = tmp_path / "tcp"
    tcp.write_text(_PROC_NET_TCP, encoding="utf-8")  # 2 distinct routable remotes
    tcp6 = tmp_path / "tcp6"
    tcp6.write_text("", encoding="utf-8")
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP", str(tcp))
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP6", str(tcp6))
    monkeypatch.setattr(conn_mod, "_MAX_TRACKED_REMOTES", 1)

    probe = ConnectionProbe(Config(), 0.0)
    probe._sample_once()  # the cap is hit here (2 remotes, cap 1)

    marker = next(
        o for o in probe.snapshot()
        if o.kind == KIND_CONNECTION_FREQUENCY and o.identity == "conn:freq:incomplete"
    )
    assert marker.attributes["monitoring_incomplete"] is True
    assert "distinct remotes" in marker.attributes["reason"]

    # the overflow is recorded (and visible) *before* the window resets - a
    # second snapshot with nothing new sampled must not still be showing it
    assert all(
        o.identity != "conn:freq:incomplete" for o in probe.snapshot()
    )


def test_connection_probe_failed_read_does_not_count_as_an_empty_sample(tmp_path, monkeypatch):
    from cableprobe.config import Config
    from cableprobe.probes import connections as conn_mod
    from cableprobe.probes.connections import ConnectionProbe

    tcp = tmp_path / "tcp"
    tcp.write_text(_PROC_NET_TCP, encoding="utf-8")
    tcp6 = tmp_path / "tcp6"
    tcp6.write_text("", encoding="utf-8")
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP", str(tcp))
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP6", str(tcp6))

    probe = ConnectionProbe(Config(), 0.0)

    # a real, successful sample first
    probe._sample_once()

    # then every subsequent read fails outright (permission race, vanished
    # file that still passed .exists(), ...)
    real_open = conn_mod.Path.open

    def failing_open(self, *a, **k):
        if str(self) == str(tcp):
            raise OSError("simulated read failure")
        return real_open(self, *a, **k)

    monkeypatch.setattr(conn_mod.Path, "open", failing_open)
    probe._sample_once()
    probe._sample_once()

    freq_obs = probe._frequency_observations()  # drains the window internally

    # tcp6 (present, empty) still reads fine each tick, so these partial
    # failures - one interface down, one up - still count as real samples
    # (there was genuinely nothing new to see on either); the remote found on
    # the one fully-successful tick keeps its own accurate count
    real = next(o for o in freq_obs if o.attributes.get("remote") == "8.8.8.8:443")
    assert real.attributes["sample_count"] == 3
    assert real.attributes["seen_count"] == 1

    # and the read failures are surfaced, not silently dropped
    marker = next(
        o for o in freq_obs
        if o.kind == KIND_CONNECTION_FREQUENCY and o.identity == "conn:freq:incomplete"
    )
    assert marker.attributes["monitoring_incomplete"] is True
    assert "could not read" in marker.attributes["reason"]


def test_connection_probe_every_read_failing_produces_no_false_empty_sample(
    tmp_path, monkeypatch
):
    """If EVERY attempted read fails, sample_count must stay 0 - a failed
    sample must never look identical to "sampled, and nothing was there"."""

    from cableprobe.config import Config
    from cableprobe.probes import connections as conn_mod
    from cableprobe.probes.connections import ConnectionProbe

    tcp = tmp_path / "tcp"
    tcp.write_text(_PROC_NET_TCP, encoding="utf-8")
    tcp6 = tmp_path / "tcp6"
    tcp6.write_text("", encoding="utf-8")
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP", str(tcp))
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP6", str(tcp6))
    monkeypatch.setattr(
        conn_mod.Path,
        "open",
        lambda self, *a, **k: (_ for _ in ()).throw(OSError("simulated failure")),
    )

    probe = ConnectionProbe(Config(), 0.0)
    probe._sample_once()
    probe._sample_once()

    counts, total, capped, read_failures, reads_truncated = probe._drain_window()
    assert total == 0  # not "sampled twice, found nothing"
    assert read_failures == 2
    assert reads_truncated == 0
    assert counts == {}


# --------------------------------------------------------------------------
# bounding: streamed, capped parsing before large allocations (issue 5)
# --------------------------------------------------------------------------


def test_stream_active_remotes_caps_a_huge_synthetic_table(tmp_path):
    from cableprobe.probes.connections import _stream_active_remotes

    remotes = [f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}" for i in range(1, 20_001)]
    table = tmp_path / "tcp"
    table.write_text(_synthetic_proc_net_tcp(remotes), encoding="utf-8")

    seen, truncated = _stream_active_remotes(table, ipv6=False, cap=100)
    assert truncated is True
    assert len(seen) == 100  # never grew past the cap, regardless of the 20,000 rows


def test_stream_active_remotes_duplicate_remotes_do_not_count_against_cap(tmp_path):
    from cableprobe.probes.connections import _stream_active_remotes

    # 5,000 rows (different local ports), but only 3 distinct remote IPs
    remotes = ["10.0.0.1", "10.0.0.2", "10.0.0.3"] * 1667
    table = tmp_path / "tcp"
    table.write_text(_synthetic_proc_net_tcp(remotes), encoding="utf-8")

    seen, truncated = _stream_active_remotes(table, ipv6=False, cap=100)
    assert truncated is False  # only 3 distinct entries - well under the cap
    assert seen == {("tcp", "10.0.0.1:443"), ("tcp", "10.0.0.2:443"), ("tcp", "10.0.0.3:443")}


def test_stream_active_remotes_cap_boundary_is_exact(tmp_path):
    from cableprobe.probes.connections import _stream_active_remotes

    exactly = [f"10.0.1.{i}" for i in range(1, 51)]  # 50 distinct
    table = tmp_path / "tcp"
    table.write_text(_synthetic_proc_net_tcp(exactly), encoding="utf-8")
    seen, truncated = _stream_active_remotes(table, ipv6=False, cap=50)
    assert len(seen) == 50 and truncated is False

    one_more = [f"10.0.1.{i}" for i in range(1, 52)]  # 51 distinct
    table.write_text(_synthetic_proc_net_tcp(one_more), encoding="utf-8")
    seen2, truncated2 = _stream_active_remotes(table, ipv6=False, cap=50)
    assert len(seen2) == 50 and truncated2 is True


def test_stream_outbound_observations_caps_the_snapshot(tmp_path):
    from cableprobe.probes.connections import _stream_outbound_observations

    remotes = [f"10.1.{(i >> 8) & 0xFF}.{i & 0xFF}" for i in range(1, 5001)]
    table = tmp_path / "tcp"
    table.write_text(_synthetic_proc_net_tcp(remotes), encoding="utf-8")

    obs, truncated = _stream_outbound_observations(table, ipv6=False, cap=200)
    assert truncated is True
    assert len(obs) == 200
    assert all(o.kind == KIND_OUTBOUND_CONNECTION for o in obs)


def test_connection_probe_snapshot_truncation_is_visible_as_incomplete(tmp_path, monkeypatch):
    from cableprobe.config import Config
    from cableprobe.probes import connections as conn_mod
    from cableprobe.probes.connections import ConnectionProbe

    remotes = [f"10.2.{(i >> 8) & 0xFF}.{i & 0xFF}" for i in range(1, 3001)]
    tcp = tmp_path / "tcp"
    tcp.write_text(_synthetic_proc_net_tcp(remotes), encoding="utf-8")
    tcp6 = tmp_path / "tcp6"
    tcp6.write_text("", encoding="utf-8")
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP", str(tcp))
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP6", str(tcp6))
    monkeypatch.setattr(conn_mod, "_MAX_SNAPSHOT_OBSERVATIONS", 100)

    out = ConnectionProbe(Config(), 0.0).snapshot()
    marker = next(o for o in out if o.identity == "conn:snapshot:incomplete")
    assert marker.attributes["monitoring_incomplete"] is True
    assert sum(1 for o in out if o.kind == KIND_OUTBOUND_CONNECTION) == 100


def test_stream_active_remotes_memory_is_bounded_regardless_of_input_size(tmp_path):
    """Deterministic evidence the intermediate collection is actually bounded,
    not a timing proxy: compare the traced memory delta of streaming+capping a
    huge table against a small one - both should build a similarly small
    result (the cap), not memory proportional to input size."""

    import tracemalloc

    from cableprobe.probes.connections import _stream_active_remotes

    def _peek_delta(n_rows: int, cap: int) -> int:
        remotes = [f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}" for i in range(1, n_rows + 1)]
        table = tmp_path / f"tcp_{n_rows}"
        table.write_text(_synthetic_proc_net_tcp(remotes), encoding="utf-8")
        tracemalloc.start()
        try:
            _stream_active_remotes(table, ipv6=False, cap=cap)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        return peak

    small_peak = _peek_delta(200, cap=100)
    huge_peak = _peek_delta(100_000, cap=100)

    # a 500x larger table must not translate into anywhere near 500x more
    # peak memory for the (capped) parse - it stays in the same ballpark
    assert huge_peak < small_peak * 10


def test_connection_probe_caps_tracked_remotes(tmp_path, monkeypatch):
    from cableprobe.config import Config
    from cableprobe.probes import connections as conn_mod
    from cableprobe.probes.connections import ConnectionProbe

    tcp = tmp_path / "tcp"
    tcp.write_text(_PROC_NET_TCP, encoding="utf-8")  # 2 distinct routable remotes
    tcp6 = tmp_path / "tcp6"
    tcp6.write_text("", encoding="utf-8")
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP", str(tcp))
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP6", str(tcp6))
    monkeypatch.setattr(conn_mod, "_MAX_TRACKED_REMOTES", 1)

    probe = ConnectionProbe(Config(), 0.0)
    probe._sample_once()
    assert len(probe._counts) == 1  # the second remote was refused, not tracked
    assert probe._remotes_capped is True

    # draining resets the per-window cap flag for the next phase
    probe._drain_window()
    assert probe._remotes_capped is False


async def test_connection_probe_sampler_thread_starts_and_stops(tmp_path, monkeypatch):
    import time

    from cableprobe.config import Config
    from cableprobe.probes import connections as conn_mod
    from cableprobe.probes.connections import ConnectionProbe

    tcp = tmp_path / "tcp"
    tcp.write_text(_PROC_NET_TCP, encoding="utf-8")
    tcp6 = tmp_path / "tcp6"
    tcp6.write_text("", encoding="utf-8")
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP", str(tcp))
    monkeypatch.setattr(conn_mod, "PROC_NET_TCP6", str(tcp6))

    probe = ConnectionProbe(Config(), 0.0)
    probe._sample_interval = 0.01
    await probe.start()
    time.sleep(0.1)
    await probe.stop()
    assert probe._sampler is None
    counts, total, _capped, _read_failures, _reads_truncated = probe._drain_window()
    assert total > 0  # the thread sampled while alive
    assert counts  # and actually saw the routable remotes
