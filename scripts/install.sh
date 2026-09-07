#!/usr/bin/env bash
# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT
#
# CableProbe installer for Raspberry Pi OS / Debian / Ubuntu.
#
# Installs CableProbe into an isolated virtualenv under /opt/cableprobe and
# links the `cableprobe` command into /usr/local/bin. Does NOT modify any
# system Python packages.
#
# Usage:
#   sudo ./scripts/install.sh                 # from a repo checkout
#   sudo CABLEPROBE_SOURCE=<pip-spec> ./scripts/install.sh
#
#   # once published, the one-liner form is:
#   #   curl -fsSL https://<host>/install.sh | sudo bash
#
# Environment:
#   CABLEPROBE_SOURCE   pip install target. Default: the repo this script lives
#                       in if it contains pyproject.toml, otherwise
#                       "cableprobe" (PyPI).
#   PREFIX              install root (default: /opt/cableprobe)
#   BIN_DIR            where to link the launcher (default: /usr/local/bin)

set -euo pipefail

PREFIX="${PREFIX:-/opt/cableprobe}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
VENV="${PREFIX}/venv"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "please run as root (sudo $0)"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_DIR="$(dirname -- "${SCRIPT_DIR}")"

if [ -n "${CABLEPROBE_SOURCE:-}" ]; then
    SOURCE="${CABLEPROBE_SOURCE}"
elif [ -f "${REPO_DIR}/pyproject.toml" ]; then
    SOURCE="${REPO_DIR}"
else
    SOURCE="cableprobe"
fi

# --- OS packages ---------------------------------------------------------
# CableProbe only *invokes* these as separate programs; it never links them.
APT_PACKAGES="python3 python3-venv usbutils util-linux"
if command -v apt-get >/dev/null 2>&1; then
    log "installing OS helper packages: ${APT_PACKAGES}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || warn "apt-get update failed; continuing"
    # shellcheck disable=SC2086
    apt-get install -y --no-install-recommends ${APT_PACKAGES} \
        || warn "some helper packages could not be installed"
else
    warn "apt-get not found; ensure python3, python3-venv, lsusb and lsblk are present"
fi

command -v python3 >/dev/null 2>&1 || die "python3 is required"

# --- virtualenv --------------------------------------------------------
log "creating virtualenv at ${VENV}"
mkdir -p "${PREFIX}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --quiet --upgrade pip

log "installing CableProbe from: ${SOURCE}"
"${VENV}/bin/pip" install --quiet "${SOURCE}"

# --- launcher --------------------------------------------------------
mkdir -p "${BIN_DIR}"
ln -sf "${VENV}/bin/cableprobe" "${BIN_DIR}/cableprobe"
log "linked ${BIN_DIR}/cableprobe -> ${VENV}/bin/cableprobe"

INSTALLED_VERSION="$("${VENV}/bin/cableprobe" --version 2>/dev/null || echo '?')"
log "installed ${INSTALLED_VERSION}"

cat <<EOF

CableProbe is installed. Next steps:

  cableprobe check                 # verify this host can observe properly
  sudo cableprobe run --name test  # run a session (sudo recommended)

To remove it:  sudo ${SCRIPT_DIR}/uninstall.sh
EOF
