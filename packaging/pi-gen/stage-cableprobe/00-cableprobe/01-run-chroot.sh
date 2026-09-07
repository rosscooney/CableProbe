#!/bin/bash -e
# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT
#
# Runs inside the target rootfs. Installs CableProbe into an isolated
# virtualenv; does not touch system Python packages.

# Where to install CableProbe from. Override in your pi-gen `config`:
#   export CABLEPROBE_SRC="cableprobe==0.3.3"
#   export CABLEPROBE_SRC="cableprobe @ git+https://github.com/rosscooney/CableProbe@v0.3.3"
CABLEPROBE_SRC="${CABLEPROBE_SRC:-cableprobe}"

python3 -m venv /opt/cableprobe/venv
/opt/cableprobe/venv/bin/pip install --no-cache-dir --upgrade pip
/opt/cableprobe/venv/bin/pip install --no-cache-dir "${CABLEPROBE_SRC}"

ln -sf /opt/cableprobe/venv/bin/cableprobe /usr/local/bin/cableprobe

install -d -m 0755 /var/lib/cableprobe/sessions
install -m 0644 files/motd /etc/motd

/opt/cableprobe/venv/bin/cableprobe --version || true
