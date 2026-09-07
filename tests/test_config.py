# Copyright (c) 2026 Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cableprobe.config import DEFAULT_PROBES, Config
from cableprobe.probes import PROBE_REGISTRY


def test_every_default_probe_is_registered():
    assert set(DEFAULT_PROBES) <= set(PROBE_REGISTRY)
    # no duplicates in the default list
    assert len(DEFAULT_PROBES) == len(set(DEFAULT_PROBES))


def test_defaults():
    cfg = Config()
    assert cfg.session.baseline_seconds == 30
    assert cfg.session.test_seconds == 60
    assert cfg.session.post_test_seconds == 30
    assert cfg.probes.enabled == DEFAULT_PROBES
    assert cfg.probes.capture_process_cmdline is True
    assert cfg.rules_file is None


def test_capture_process_cmdline_toggle():
    cfg = Config.model_validate({"probes": {"capture_process_cmdline": False}})
    assert cfg.probes.capture_process_cmdline is False


def test_load_none_returns_defaults():
    assert Config.load(None) == Config()


def test_load_yaml(tmp_path):
    path = tmp_path / "cfg.yaml"
    path.write_text(
        "session:\n"
        "  baseline_seconds: 5\n"
        "  test_seconds: 10\n"
        "  post_test_seconds: 7\n"
        "probes:\n"
        "  enabled: [usb, block]\n"
        "  kernel_log_backend: dmesg\n"
        "output_dir: /tmp/out\n",
        encoding="utf-8",
    )
    cfg = Config.load(path)
    assert cfg.session.baseline_seconds == 5
    assert cfg.session.test_seconds == 10
    assert cfg.probes.enabled == ["usb", "block"]
    assert cfg.probes.kernel_log_backend == "dmesg"
    assert str(cfg.output_dir) == "/tmp/out"


def test_negative_duration_rejected():
    with pytest.raises(ValidationError):
        Config.model_validate({"session": {"test_seconds": -1}})


def test_unknown_kernel_backend_rejected():
    with pytest.raises(ValidationError):
        Config.model_validate({"probes": {"kernel_log_backend": "syslog"}})


def test_missing_config_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        Config.load(tmp_path / "nope.yaml")


def test_non_mapping_config_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("- 1\n- 2\n", encoding="utf-8")
    with pytest.raises(ValueError):
        Config.load(path)
