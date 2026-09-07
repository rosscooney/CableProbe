#!/bin/bash -e
# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

if [ ! -d "${ROOTFS_DIR}" ]; then
	copy_previous
fi
