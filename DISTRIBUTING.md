<!--
Copyright (c) 2026 Stable State Consulting Ltd
SPDX-License-Identifier: MIT
-->

# Distributing CableProbe

CableProbe is MIT-licensed. The distribution model is deliberately
**low-friction**: this project ships **only its own MIT code and recipes**, and
never redistributes a prebuilt operating-system image. Users assemble the
runnable environment from stock Raspberry Pi OS / Debian, so the GPL/LGPL parts
of the OS come straight from Raspberry Pi Ltd and Debian — this project is not
in that supply chain.

> Not legal advice. If you redistribute at scale, have a solicitor review your
> final artifact and its notices.

## Three supported ways to install

### 1. pip / pipx (any Debian/Ubuntu/RPi OS host)

```bash
pipx install cableprobe          # isolated, recommended
# or
python3 -m venv ~/.venvs/cableprobe
~/.venvs/cableprobe/bin/pip install cableprobe
```

`pyudev` (LGPL-2.1, Linux-only) and the other Python deps are pulled from PyPI
as normal, unmodified, replaceable packages. CableProbe also invokes `lsusb`,
`lsblk`, `journalctl` and `dmesg` — install `usbutils` and `util-linux` if they
are not already present (`journalctl`/`dmesg` ship with the base OS).

### 2. `scripts/install.sh` (one command on a Pi)

```bash
sudo ./scripts/install.sh
# once published:
# curl -fsSL https://raw.githubusercontent.com/rosscooney/CableProbe/main/scripts/install.sh | sudo bash
```

Creates `/opt/cableprobe/venv`, installs the package there, links
`/usr/local/bin/cableprobe`, and `apt-get install`s the helper CLI tools. It
does **not** modify system Python packages. Remove with
`sudo scripts/uninstall.sh`.

### 3. Disposable Raspberry Pi image (build-your-own)

Use the pi-gen custom stage in [`packaging/pi-gen/`](packaging/pi-gen/). You run
Raspberry Pi's official image builder; it fetches stock Raspberry Pi OS and adds
CableProbe on top via `pip`. The output is a headless image you flash, use once
against a suspect cable, and re-flash.

This project distributes the **recipe**, not the image. If *you* then hand the
built `.img` to other people, see the licensing notes in
[`packaging/pi-gen/README.md`](packaging/pi-gen/README.md): keep the OS packages
unmodified, ship the recipe + your `config` for reproducibility, and keep `pip`
on the image so LGPL components stay replaceable.

## Why this keeps licensing simple

| Scenario | Who distributes the GPL/LGPL OS | Your obligation |
|----------|-------------------------------|-----------------|
| pip / pipx / `install.sh` | Raspberry Pi Ltd + Debian (user's existing OS) | none for the OS; ship CableProbe's `LICENSE` + `NOTICE.md` |
| build-your-own image (this repo's recipe) | Raspberry Pi Ltd + Debian, at build time on the user's machine | none for the OS |
| **you** re-hand a built `.img` to third parties | **you** | pass along OS licences + a written offer / source pointer for any GPL/LGPL binaries; easiest if you never modify them |

CableProbe's own code stays MIT in every case. Calling `lsusb`/`lsblk`/etc. as
separate programs via `subprocess` is arms-length execution, not a derivative
work, regardless of those tools' licences.

## Publishing checklist (maintainers)

See [RELEASING.md](RELEASING.md) for the full step-by-step. In short:

- [ ] `python -m build` → `twine check dist/*` passes
- [ ] `pip install dist/*.whl` in a clean venv; `cableprobe --version` works
- [ ] tag `v0.3.1`; publish to PyPI as `cableprobe`
- [ ] confirm `CABLEPROBE_SRC` / install one-liner point at
      `github.com/rosscooney/CableProbe` (and PyPI once published)
- [ ] `LICENSE`, `NOTICE.md`, `CONTRIBUTING.md`, `SECURITY.md` present in sdist
