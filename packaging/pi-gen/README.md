<!--
Copyright (c) 2026-present Stable State Consulting Ltd
SPDX-License-Identifier: MIT
-->

# Building a disposable CableProbe image with pi-gen

This directory is a **pi-gen custom stage**. pi-gen is Raspberry Pi's official
image builder; you run it, it downloads stock Debian/Raspberry Pi OS packages
and assembles an image. CableProbe is added on top as one small stage.

CableProbe (this repo) ships **only the recipe**, not a prebuilt image. You
build the image yourself from stock Raspberry Pi OS, so the only thing being
redistributed by this project is the MIT-licensed CableProbe code. See
[`DISTRIBUTING.md`](../../DISTRIBUTING.md) for why that keeps things simple.

## Prerequisites

- A Debian/Ubuntu build host (or the official pi-gen Docker workflow).
- `git`, plus the build deps listed in the pi-gen README.
- Network access (pi-gen downloads packages; the stage `pip install`s
  CableProbe).

## Procedure

```bash
# 1. Get pi-gen
git clone https://github.com/RPi-Distro/pi-gen
cd pi-gen

# 2. Drop in the CableProbe stage
cp -r /path/to/cableprobe/packaging/pi-gen/stage-cableprobe ./stage-cableprobe

# 3. Configure
cp /path/to/cableprobe/packaging/pi-gen/config.example ./config
$EDITOR ./config        # set CABLEPROBE_SRC, user/pass, locale, SSH...

# 4. Build (Docker route is easiest)
./build-docker.sh
#   or the native route:
# sudo ./build.sh

# 5. Image lands in ./deploy/ as *-cableprobe.img.xz
```

Flash with Raspberry Pi Imager / `dd`, boot the Pi, log in, and:

```bash
cableprobe check
sudo cableprobe run --name suspect-cable-01
```

Re-flash the card between suspect cables — that is the "disposable" part.

## What the stage does

| File | Effect |
|------|--------|
| `00-cableprobe/00-packages` | apt-installs `usbutils`, `util-linux`, `python3-venv` (invoked as separate programs; never linked) |
| `00-cableprobe/01-run-chroot.sh` | creates `/opt/cableprobe/venv`, `pip install`s `$CABLEPROBE_SRC`, links `/usr/local/bin/cableprobe`, creates `/var/lib/cableprobe/sessions`, installs the MOTD |
| `EXPORT_IMAGE` | tells pi-gen to emit an image with an `-cableprobe` suffix |

It does **not** modify any GPL/LGPL OS package. Everything under
`/opt/cableprobe` is CableProbe (MIT) and its Python dependencies, fetched at
build time from PyPI.

## Licensing notes for the image you produce

The image is an aggregate of independently-licensed software. You are
redistributing stock Raspberry Pi OS plus CableProbe. To stay clean:

- Don't patch or rebuild the OS packages — keep them exactly as pi-gen fetched
  them, so "corresponding source" is what Debian/Raspberry Pi already publish.
- Ship this recipe (or a link to it) and your `config` alongside the image, so
  the image is reproducible.
- Keep `pip` on the image (it is) so LGPL components such as `pyudev` remain
  user-replaceable.
- Include CableProbe's `LICENSE` and `NOTICE.md` (they are installed with the
  package metadata under `/opt/cableprobe/venv`).

If you distribute the image widely, also include a short `THIRD-PARTY` notice
pointing users at `https://www.raspberrypi.com/software/` and the Debian source
archives for the OS components.
