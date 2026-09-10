#!/bin/bash -e
# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

if [ ! -d "${ROOTFS_DIR}" ]; then
	copy_previous
fi
