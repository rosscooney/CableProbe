<!--
Copyright (c) 2026 Stable State Consulting Ltd
SPDX-License-Identifier: MIT
-->

# Changelog

All notable changes to CableProbe are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/).
Each release is also published to
[PyPI](https://pypi.org/project/cableprobe/) and tagged on
[GitHub](https://github.com/rosscooney/CableProbe/releases).

## [Unreleased]

## [0.3.9] - 2026-09-09

More noise reduction from real-device testing on a Raspberry Pi 5 — an external
USB disk, a USB ethernet adapter and a power bank — plus a convenience command
and a CI fix.

### Added

- `cableprobe link` — symlinks the launcher into `/usr/local/bin` (`--bin-dir`
  to choose, `--remove` to undo) so `sudo cableprobe run` works without a full
  path after a `pipx` / `pip install --user` install. The not-root warning now
  points at it.

### Changed

- Findings that hit the same rule are consolidated into one. A single event (an
  ethernet gadget enumerating, say) matched a kernel-log rule on half a dozen
  separate log lines and became six CRITICAL findings; it is now one finding
  that lists each match. A USB ethernet adapter scan goes from 11 findings to 5.
- Removed the broad `usb-ethernet-gadget-kernel-signature` (CRITICAL) rule -
  `network-interface-appeared-on-connect` and `gadget-driver-module-loaded`
  already cover a network gadget, at HIGH. A new `rndis-gadget-kernel-signature`
  (HIGH) keeps a rule for RNDIS specifically, which legitimate USB ethernet
  dongles do not use. CRITICAL is now reserved for a gadget that actually took
  over routing / DNS or tunnelled PCIe.
- A `kernel_message` finding no longer prints "did NOT revert after disconnect"
  — a log line, once emitted, is in the log for the rest of the session, so that
  was always true and meaningless.
- `udev_monitor` only reports events for subsystems that map to a real device
  kind. Plugging in one USB disk fires a swarm of kernel-internal `add` events
  (`scsi_device`, `scsi_disk`, `scsi_generic`, `bsg`, `bdi`, …) that were being
  turned into `<subsystem>_device` "transient devices"; block-device partition
  events are dropped too (the disk covers them).
- A delta is `transient` only when the device was **both added and removed
  within the same phase** — a genuine plug-and-vanish. A device that is added
  and then stays (or is removed later, in post-test) is handled by the normal
  snapshot comparison. Together with the `udev_monitor` change this takes an
  external-USB-disk scan from ~20 findings to 4.
- CI: the publish workflow's `actions/*` steps bumped to the Node 24 majors
  (checkout v7, setup-python v7, upload-artifact v7, download-artifact v8),
  clearing the "Node.js 20 is deprecated" warning. No effect on the package.

## [0.3.8] - 2026-09-09

Noise reduction, mostly around Wi-Fi. Testing an external USB hard disk, and
even a USB light, on a Raspberry Pi 5 (which has Wi-Fi) was producing 20-plus
deltas and a fistful of **HIGH** findings — all of it the operator's own
enterprise Wi-Fi, not the cable.

### Added

- This changelog, covering every earlier tagged release.

### Changed

- **`wifi_scan` is no longer a default probe.** On any premises with Wi-Fi it
  produced a dozen-plus deltas and findings per session (neighbouring APs drift
  in and out of scan range on their own). Enable it in `probes.enabled` when you
  specifically suspect the cable carries a radio and can baseline somewhere
  RF-quiet.
- The one Wi-Fi rule (`strong-wifi-ap-appeared-and-reverted`, replacing
  `strong-wifi-ap-appeared-on-connect` and the `wifi-ap-appeared-on-connect`
  catch-all) requires a **strong** AP from a **vendor not seen at baseline**
  that appeared on connect **and vanished on disconnect**. Enterprise / mesh
  APs (UniFi, Aruba, …) broadcast a rotating set of BSSIDs per physical unit, so
  the probe now groups them by vendor OUI (`family_new_this_session`) instead of
  exact BSSID. `signal_dbm` / `strong_signal` / `channel` are treated as
  volatile, so RSSI drift no longer creates "modified" deltas.
- `gadget-driver-module-loaded-on-connect` no longer matches storage drivers
  (`usb_storage` / `uas` / `sg`) — they load for any USB disk, and the block /
  mount probes already flag storage. It now covers network / serial / Bluetooth
  gadget drivers. The generic `kernel-module-loaded-on-connect` (LOW) rule was
  removed — for a normal device the modules that load are all expected.
- `mass-storage-appeared-generic` (MEDIUM) only fires when the transport could
  NOT be confirmed as USB / hotplug / removable, so a confirmed USB disk gets
  one HIGH finding instead of HIGH + MEDIUM.
- `block` probe no longer emits partitions as their own observations — they are
  summarised (`partitions`, `partition_count`) onto the parent disk.

## [0.3.7] - 2026-09-07

Less noise on a live host, and an interactive report picker. A HID device on an
unknown cable still flags **HIGH** — that is the BadUSB signature, and CableProbe
cannot tell a real keyboard from an implant — but the surrounding output was
noisy on a Pi with other things running.

### Added

- `cableprobe report` with no path lists the saved reports (numbered, newest
  first, with session name / date / severity) and asks which one to open. New
  `--output-dir` / `--config` options on the command.
- `probes.kernel_log_verbose` config option to restore the full kernel-log
  firehose.

### Changed

- The "did not revert" heads-up counts only real device kinds. Kernel log lines
  (which only ever accumulate) and processes no longer inflate it.
- `kernel_log` defaults to *notable* lines only — enumeration failures and
  network/serial gadget-driver classes. Routine `New USB device found` /
  `Product:` / `input: X as …` chatter now needs `kernel_log_verbose` (the
  `usb` / `input` / `usb_descriptors` probes already carry it, structured).
- `input` merges the several HID collections of one physical USB device
  (keyboard + consumer-control + system-control) into one observation.
- `process` drops trivial shell/cron plumbing (`sleep`, `flock`, …) and the
  helper subprocesses CableProbe itself runs (`lsusb`, `ss`, `journalctl`, …).
- Advice: the "a USB hub appeared" line fires only for an actual new hub, not
  for the device count rising by one.

## [0.3.6] - 2026-09-07

### Added

- Plain-language **"What this means"** box at the end of the console summary
  (`cableprobe/advice.py`). An overall verdict keyed to severity — from "treat
  this cable as hostile hardware" down to "nothing notable", always with the
  reminder that a clean result is "nothing happened this time", not "nothing can
  happen" — plus one plain sentence per thing observed (BadUSB input device,
  network redirection, storage payload, hidden serial channel, covert
  audio/video, the cable's own Wi-Fi, PCIe/DMA, an unexpected driver, a hidden
  hub, a new listener, a new process), and a heads-up when something did not
  revert after disconnect. Renders as a coloured panel, or a plain
  `=== WHAT THIS MEANS ===` block under `-v`, without `rich`, or in
  `cableprobe report`.

## [0.3.5] - 2026-09-07

A bare safe cable and an ordinary USB keyboard were both producing dozens of
spurious phase-differences and findings. Fixed without weakening real detection.

### Added

- `not_contains` attribute condition for detection rules.

### Changed

- `listeners` drops `LISTEN` sockets on ephemeral-range ports (at or above the
  kernel's `ip_local_port_range` low bound, default 32768) — RPC, mDNS and IDE
  remote-helper sockets churn these constantly and no implant binds a backdoor
  to a port that moves on every restart.
- `process` skips kernel threads (`kworker/*`, `ksoftirqd/*`, … — children of
  `kthreadd`).
- `input` keeps only the logical `inputN` node, not its `eventN` / `mouseN`
  char-device children (the udev `input` subsystem lists each device twice).
- Rule `new-listener-on-connect` lowered **medium → low**.
- Rule `hid-generic-appeared-on-connect` no longer double-reports a keyboard or
  pointer that already matched its own higher-severity rule.

## [0.3.4] - 2026-09-07

### Added

- Per-phase progress bar during `cableprobe run` — description, bar, percent,
  `elapsed/total s` and estimated time remaining, one per phase, each filling to
  100% and staying on screen. `-v` / `-vv` keeps the plain
  `[phase] 12.0/30s (40%)` text lines instead; degrades cleanly when stdout is
  not a terminal and works with `--auto`.

## [0.3.3] - 2026-09-07

### Changed

- Documentation and `cableprobe --help` clarify that connector type does not
  matter: CableProbe watches how the host reacts, so a **USB-A** implant cable
  (the original O.MG form factor) is fully in scope. The `usbc_pd` probe stays
  USB-C specific and skips cleanly on a USB-A-only host. Docs / help text only,
  no behaviour change.

## [0.3.2] - 2026-09-07

### Fixed

- `sudo cableprobe` gave `command not found` for a `pipx` / `pip install --user`
  install (the launcher lives in `~/.local/bin`, which is not on root's
  `secure_path`). The not-root warning now resolves the launcher and prints
  commands that work: `sudo <absolute path> …`,
  `sudo env "PATH=$PATH" cableprobe …`, or `sudo ./scripts/install.sh` for a
  permanent `/usr/local/bin` symlink. A launcher already on root's `PATH` still
  gets the plain `sudo cableprobe …`.

### Changed

- `scripts/install.sh` and the pi-gen recipe now `apt install` `iw` (for
  `wifi_scan`) and `pciutils`.
- README gains a "command not found" troubleshooting note and flags
  `scripts/install.sh` as the recommended test-rig install.

## [0.3.1] - 2026-09-07

### Added

- **`wifi_scan`** probe — Wi-Fi access points in range. Several cable implants
  carry a radio and run their own AP for out-of-band control. Active `iw` /
  `nmcli` scan at each phase boundary (never per-tick), flags APs strong enough
  (≥ −55 dBm) to plausibly be in the connector, never associates.
- **`keystroke_cadence`** probe — key-press *timing* per input device. The key
  `code` of every event is discarded, so it only learns *when* keys were
  pressed, not which. Flags superhuman speed or machine-perfect regularity as
  injection. Toggle with `probes.capture_keystroke_timing`.
- Rules `keystroke-injection-detected` (**critical**) and
  `strong-wifi-ap-appeared-on-connect` (**high**), plus lower-confidence
  variants. 20 probes, 38 rules total.
- `metadata.probes_unavailable` field in the report.
- `cableprobe run` detects when it is not running as root, prints the `sudo`
  command, and (interactive) asks whether to continue; `--auto` warns and
  proceeds. `cableprobe check` flags it too.

### Changed

- Probes whose kernel interface is absent (no Type-C class, no `/sys/bus/pci`,
  no Wi-Fi) are dropped up front and shown as a single dim `skipped: …` line
  instead of a yellow "Probe warnings" block.
- `cableprobe --version` reflects the installed package version (was pinned at
  `0.1.0`).
- Test suite 57 → 124.

## [0.1.2] - 2026-09-07

### Added

- Eleven observation probes: `serial`, `audio`, `video`, `usb_descriptors`,
  `usb_topology`, `usbc_pd`, `kernel_modules`, `mounts`, `pci`, `routing`,
  `listeners`. All observation-only; each skips cleanly when its kernel
  interface is absent.
- 17 detection rules, including **critical** rules for PCIe / Thunderbolt
  tunnelling and default-route / DNS hijack.
- Project home page <https://www.cableprobe.com>; author / security contact
  `contributors@cableprobe.com`.

### Changed

- Default probe set expanded from 7 to 18 (all opt-out via `probes.enabled`).
- Project URLs point at the public GitHub repository and PyPI.
- Test suite 57 → 83.

## [0.1.0] - 2026-09-07

Initial release.

### Added

- Three-phase (`baseline` / `test` / `post_test`) observation session for an
  unknown USB cable on a sacrificial Linux host.
- Probes: `udev_monitor`, `usb`, `block`, `network`, `input`, `process`,
  `kernel_log`.
- Phase-delta analysis and a YAML-configurable detection-rules engine with a
  packaged default ruleset.
- Structured JSON report (mode `0600`) plus a console summary; `cableprobe run`,
  `check`, `probes`, `rules`, `report` commands.
- `--fail-on-findings` exit codes (`10` / `20` / `30` for medium / high /
  critical).
- Packaging: PyPI (`cableprobe`), `scripts/install.sh` for a Raspberry Pi, and a
  pi-gen custom stage for a build-your-own disposable image.

[Unreleased]: https://github.com/rosscooney/CableProbe/compare/v0.3.9...HEAD
[0.3.9]: https://github.com/rosscooney/CableProbe/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/rosscooney/CableProbe/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/rosscooney/CableProbe/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/rosscooney/CableProbe/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/rosscooney/CableProbe/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/rosscooney/CableProbe/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/rosscooney/CableProbe/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/rosscooney/CableProbe/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/rosscooney/CableProbe/compare/v0.1.2...v0.3.1
[0.1.2]: https://github.com/rosscooney/CableProbe/compare/v0.1.0...v0.1.2
[0.1.0]: https://github.com/rosscooney/CableProbe/releases/tag/v0.1.0
