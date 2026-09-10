# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Standard-library logging setup for CableProbe."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_LOGGER_NAME = "cableprobe"

_LEVELS = {
    0: logging.WARNING,
    1: logging.INFO,
    2: logging.DEBUG,
}


def setup_logging(verbosity: int = 0, logfile: Path | None = None) -> logging.Logger:
    """Configure the root logger and return the ``cableprobe`` logger.

    ``verbosity`` maps 0 -> WARNING, 1 -> INFO, 2+ -> DEBUG.
    """

    level = _LEVELS.get(verbosity, logging.DEBUG)

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if logfile is not None:
        logfile = Path(logfile)
        logfile.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(logfile, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=handlers,
        force=True,
    )
    return logging.getLogger(_LOGGER_NAME)


def get_logger(name: str | None = None) -> logging.Logger:
    if name:
        return logging.getLogger(f"{_LOGGER_NAME}.{name}")
    return logging.getLogger(_LOGGER_NAME)
