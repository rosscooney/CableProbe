# CableProbe

**CableProbe is an open-source defensive USB cable analysis tool for Linux**
(developed and tested on Raspberry Pi OS / Debian, and reasonably portable to
other Debian/Ubuntu systems).

- Home page: <https://www.cableprobe.com>
- Source & downloads: <https://github.com/rosscooney/CableProbe>
  ([releases](https://github.com/rosscooney/CableProbe/releases))
- Package: [`cableprobe` on PyPI](https://pypi.org/project/cableprobe/)

CableProbe watches a sacrificial Linux host while you connect an *unknown*
USB-C-to-USB-C cable, then compares before, during and after to surface hidden
HID devices, rogue network gadgets, mass storage, serial channels, transient
enumeration and kernel errors.

CableProbe **only observes, records and reports**. It does not inject payloads,
exploit anything, capture credentials, establish persistence or provide remote
access. It is a monitoring tool for a sacrificial test host.

> ⚠️ CableProbe **cannot prove that a cable is safe or uncompromised.** A clean
> report means CableProbe did not observe anything notable during that session,
> not that the cable is benign. Use it as one input to your own judgement.

> ⚠️ Run this on a dedicated, disposable Raspberry Pi that holds no sensitive
> data and is isolated from networks you care about. Treat any cable under test
> as hostile hardware.

## How it works

A session has three phases:

| Phase       | What happens                                                              |
|-------------|--------------------------------------------------------------------------|
| `baseline`  | Observe the Pi *before* the unknown cable is connected.                  |
| `test`      | You connect / power the unknown cable; CableProbe keeps observing.       |
| `post_test` | You disconnect the cable; CableProbe observes the return to baseline.    |

CableProbe then compares the three phases and writes a structured JSON report
describing everything that **appeared, disappeared or changed** in correlation
with the cable, and runs a set of YAML-configurable detection rules over those
differences to produce prioritised findings.

### Probes (observation only)

| Probe             | Observes                                                                         |
|-------------------|---------------------------------------------------------------------------------|
| `udev_monitor`    | Live udev add/remove/change events across all subsystems.                        |
| `usb`             | USB device inventory (vendor/model, interface classes, HID, hub).                |
| `usb_descriptors` | Per-interface USB descriptors from sysfs (class/subclass/driver/endpoints).      |
| `usb_topology`    | USB hub/port tree — hub count, device count, depth, per-hub inventory.           |
| `usbc_pd`         | USB-C / Power Delivery port + partner state: data/power roles, alt modes.        |
| `block`           | Block devices and their transport (`lsblk`).                                     |
| `mounts`          | Filesystem mounts backed by a device or under removable-media paths.             |
| `network`         | Network interfaces, drivers, USB-ness, addresses.                                |
| `routing`         | Default route and DNS resolvers (gateway / resolver hijack).                     |
| `listeners`       | TCP sockets in `LISTEN` state (with owning process when `ss` is present).        |
| `input`           | Input / HID devices (keyboards, mice, tablets).                                  |
| `serial`          | Serial / modem (TTY) devices, including USB serial (CDC-ACM, FTDI, cp210x).      |
| `audio`           | Audio (sound-card) devices, including USB audio class.                           |
| `video`           | video4linux camera / capture devices, including UVC.                             |
| `pci`             | PCI and Thunderbolt devices (USB4/TBT PCIe-tunnel / DMA surface).                |
| `kernel_modules`  | Loaded kernel modules — catches gadget drivers loaded on connect.                |
| `wifi_scan`       | Wi-Fi APs in range (an implant cable may run its own AP). Active scan, boundary-only. |
| `keystroke_cadence` | Key-press *timing* per input device — flags superhuman / robotic typing.       |
| `process`         | Processes started after the session began.                                       |
| `kernel_log`      | USB-relevant kernel / journal lines emitted during the session.                  |

Probes that need hardware or kernel interfaces the host does not expose (no
Type-C class, no `/sys/bus/pci`, …) are skipped automatically. `cableprobe
check` lists them as `FAIL` with the reason, and a run notes them once as
`skipped: … (interface not present on this host)` — that is expected, not an
error. Raspberry Pi 4, for example, has no `usbc_pd` (its USB-C port is
power-only); Raspberry Pi 5 does. To silence a skip entirely, drop the probe
from `probes.enabled` in your config.

Two probes have side effects worth knowing about:

- `wifi_scan` runs an **active** Wi-Fi scan (`iw` / `nmcli`) at each phase
  boundary, which briefly interrupts any Wi-Fi association on that interface. It
  never associates with a discovered AP.
- `keystroke_cadence` reads `/dev/input/event*` for key-press **timing only** —
  the key `code` of every event is discarded before anything is stored, so it
  never learns which keys were pressed. Set `capture_keystroke_timing: false`
  to disable it.

## Install

Requires Python 3.11+. See [DISTRIBUTING.md](DISTRIBUTING.md) for the full
picture; the short version:

```bash
# 1. pip / pipx on an existing Raspberry Pi OS / Debian host
pipx install cableprobe
sudo apt install usbutils util-linux        # CLI tools CableProbe shells out to

# 2. one command on a Pi (isolated venv under /opt/cableprobe)
sudo ./scripts/install.sh                    # sudo scripts/uninstall.sh to remove

# 3. from a checkout, for development
git clone https://github.com/rosscooney/CableProbe cableprobe && cd cableprobe
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

For a **disposable Raspberry Pi image**, build your own from stock Raspberry Pi
OS using the pi-gen custom stage in [`packaging/pi-gen/`](packaging/pi-gen/) —
CableProbe ships the recipe, not a prebuilt image.

`pyudev` needs `libudev` (present on Raspberry Pi OS / Debian). On non-Linux
hosts CableProbe still installs and its `--help` / `check` / `report` commands
work, but the live probes are unavailable.

## Upgrading

```bash
# 1a. pipx — to the latest *published* release on PyPI
pipx upgrade cableprobe
pipx upgrade-all                          # everything pipx manages
pipx install --force cableprobe==0.3.1    # pin / roll back to a specific release

# 1b. pipx — to the latest development code (main), ahead of the last release
pipx install --force "git+https://github.com/rosscooney/CableProbe"
pipx install --force "cableprobe @ git+https://github.com/rosscooney/CableProbe@main"

# 2. scripts/install.sh — re-run against a fresh checkout; reinstalls
#    into /opt/cableprobe/venv in place
git -C cableprobe pull && sudo ./cableprobe/scripts/install.sh

# 3. development checkout
git pull && pip install -e ".[dev]"
```

Check what you have and that the host is still ready afterwards:

```bash
cableprobe --version
cableprobe check
```

`pipx upgrade cableprobe` only moves you to a **higher version number on PyPI**.
`cableprobe is already at latest version 0.3.1` means there is no newer release
— publish one first (bump `version` in `pyproject.toml`, tag, push to PyPI), or
use the `git+https://…` form above to track `main`. If a new version drops a
probe or changes report fields it is called out in the GitHub release notes;
saved `.cableprobe.json` reports from older versions still open with
`cableprobe report`.

## Usage

```bash
# Check the host is ready
cableprobe check

# Run a session (you will be prompted before each phase)
sudo cableprobe run --name "suspect-cable-01" \
    --baseline 30 --test 90 --post-test 30

# Unattended / rig mode: advance phases on a timer instead of prompts
sudo cableprobe run --auto --baseline 20 --test 60 --post-test 20

# Inspect a saved report
cableprobe report cableprobe-sessions/2026*.cableprobe.json
cableprobe report <file> --format json | jq .

# See / customise detection rules
cableprobe rules
cableprobe rules my-rules.yaml
```

Running with `sudo` is strongly recommended: without root the kernel-log,
udev-attribute, USB-descriptor, keystroke-timing and raw-socket probes see much
less detail and some are skipped entirely. `cableprobe run` detects this and, in
interactive mode, prints the `sudo` command and asks whether to continue anyway;
`--auto` just warns and proceeds. `cableprobe check` flags it too.

### Exit codes

`cableprobe run --fail-on-findings` exits `10` / `20` / `30` for the highest
finding severity (`medium` / `high` / `critical`), otherwise `0`. Without the
flag, `run` always exits `0` on a completed session.

## Configuration

Optional YAML config (`--config cableprobe.yaml`):

```yaml
session:
  baseline_seconds: 30
  test_seconds: 90
  post_test_seconds: 30
  sample_interval_seconds: 2.0
probes:
  # default: all probes; list a subset to narrow the session
  enabled: [udev_monitor, usb, usb_descriptors, usb_topology, usbc_pd, block,
            mounts, network, routing, listeners, input, serial, audio, video,
            pci, kernel_modules, wifi_scan, keystroke_cadence, process, kernel_log]
  kernel_log_backend: auto        # auto | journalctl | dmesg
  kernel_log_keywords: []         # extra case-insensitive substrings to keep
  capture_process_cmdline: true   # false => store only the executable name
  capture_keystroke_timing: true  # false => disable the keystroke_cadence probe
rules_file: null                  # null => packaged default rules
output_dir: ./cableprobe-sessions
```

Reports are written with mode `0600` (they can contain host details, MAC
addresses and process command lines). All device-supplied text (USB descriptor
strings, device names, kernel log lines) is stripped of control characters and
length-bounded before it is stored or shown, so a hostile cable cannot inject
terminal escape sequences via the report or the console summary.

### Detection rules

Rules live in YAML (see `cableprobe/data/default_rules.yaml`). Each rule matches
a phase *delta* and raises a finding:

```yaml
- id: hid-keyboard-appeared-on-connect
  title: HID keyboard appeared while the unknown cable was connected
  severity: high
  rationale: >
    A keyboard-class HID device that enumerates only when the cable is
    connected is the classic BadUSB signature.
  match:
    change: appeared          # appeared | disappeared | modified
    first_seen_phase: test    # baseline | test | post_test
    kind: [input_device, hid_device]
    attributes:
      any:
        - { key: ID_INPUT_KEYBOARD, equals: "1" }
```

Match keys: `change`, `kind`, `first_seen_phase`, `reverted_after_disconnect`,
`transient`, `label_regex`, `event_action`, and `attributes.all` / `attributes.any`
(conditions: `equals`, `not_equals`, `exists`, `contains`, `regex`).

## Report structure

```jsonc
{
  "metadata":  { "session_name", "host", "config", "probes_used", "probe_warnings", ... },
  "phases":    { "baseline": {...}, "test": {...}, "post_test": {...} },
  "deltas":    [ { "change", "kind", "identity", "label",
                   "first_seen_phase", "present_in",
                   "reverted_after_disconnect", "transient",
                   "attributes", "attribute_changes", "related_events" } ],
  "findings":  [ { "rule_id", "title", "severity", "rationale", "evidence" } ],
  "summary":   { "delta_count", "cable_correlated_change_count",
                 "findings_by_severity", "highest_severity", ... }
}
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

The analysis, rules and report layers are pure and fully unit-tested without
hardware. Each probe keeps a pure parser (of `lsusb` / `lsblk` / `/proc`
output) or sysfs-tree scanner that is tested against captured samples or a
fake `/sys` tree — see `tests/test_probes_parsing.py` and
`tests/test_probes_new.py`.

The source lives at <https://github.com/rosscooney/CableProbe>. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute,
[SECURITY.md](SECURITY.md) for how to report vulnerabilities privately, and
[RELEASING.md](RELEASING.md) for how maintainers cut a release to PyPI.

## Scope / non-goals

* CLI only — no web dashboard.
* The `usbc_pd` probe reads the kernel's USB-C / Power Delivery port state
  (data/power roles, alternate modes); CableProbe does **not** do electrical
  measurement of the cable itself — no voltage/current sampling, no e-marker
  interrogation.
* No offensive capability of any kind, by design.

## Third-party dependencies

CableProbe does not copy or vendor third-party source code. It depends on a
small set of Python libraries and, at runtime, invokes standard Linux
command-line tools as separate, independently installed programs. See
[NOTICE.md](NOTICE.md) and the "Third-party licensing" note below in the repo
history / `docs`.

Direct Python dependencies and their licences:

| Package          | Licence            | Notes                                          |
|------------------|--------------------|------------------------------------------------|
| typer            | MIT                | CLI framework                                  |
| pydantic         | MIT                | data models                                    |
| psutil           | BSD-3-Clause       | process / network inventory                    |
| PyYAML           | MIT                | config and rules parsing                       |
| rich             | MIT                | console rendering                              |
| pyudev           | **LGPL-2.1-or-later** | Linux-only; imported as a library — see note |
| pytest, pytest-asyncio (dev only) | MIT, Apache-2.0 | test suite                        |

**Note on `pyudev`:** `pyudev` is LGPL-2.1-or-later. It is a normal, separately
installed Python dependency that CableProbe imports; it is not vendored or
modified. Distributing an MIT-licensed project that depends on an unmodified
LGPL library is standard practice, provided `pyudev` remains replaceable and its
source stays available (it is, from PyPI). If you redistribute CableProbe as a
bundled binary/image, keep `pyudev` as a replaceable component and include its
licence text. The Linux CLI tools CableProbe shells out to (`lsusb`/usbutils,
`lsblk`/`dmesg`/util-linux — GPL-2.0; `journalctl`/systemd — LGPL-2.1) are
invoked as independent programs and do not affect CableProbe's MIT licensing.

## Licence

CableProbe is open-source software created by Stable State Consulting Ltd and
released under the MIT License.

Copyright © 2026 Stable State Consulting Ltd.

See [LICENSE](LICENSE) for details.
