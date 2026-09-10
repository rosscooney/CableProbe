#!/usr/bin/env bash
# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT
#
# Remove a CableProbe install created by scripts/install.sh.
# Does not touch OS helper packages (usbutils, util-linux) or session reports.

set -euo pipefail

PREFIX="${PREFIX:-/opt/cableprobe}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"

[ "$(id -u)" -eq 0 ] || { echo "please run as root (sudo $0)" >&2; exit 1; }

if [ -L "${BIN_DIR}/cableprobe" ]; then
    rm -f "${BIN_DIR}/cableprobe"
    echo "removed ${BIN_DIR}/cableprobe"
fi

if [ -d "${PREFIX}" ]; then
    rm -rf "${PREFIX}"
    echo "removed ${PREFIX}"
fi

echo "done. (OS helper packages and any session reports were left in place)"
