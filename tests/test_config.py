"""Tests for configuration validation and persistence."""

import json

import pytest

from cryptosuite.config import (
    AppConfig,
    config_directory,
    load_config,
    save_config,
    update_config,
)
from cryptosuite.utils.exceptions import ConfigurationError


def test_missing_config_uses_secure_defaults(tmp_path):
    config = load_config(tmp_path / "missing.json")
    assert config == AppConfig(logging_enabled=False, debug=False, log_level="INFO")


def test_config_round_trip(tmp_path):
    target = tmp_path / "nested" / "config.json"
    expected = AppConfig(logging_enabled=True, debug=True, log_level="WARNING")
    assert save_config(expected, target) == target
    assert load_config(target) == expected


def test_unknown_config_field_is_rejected(tmp_path):
    target = tmp_path / "config.json"
    target.write_text(json.dumps({"secret": "must-not-be-here"}), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Unknown configuration"):
        load_config(target)


@pytest.mark.parametrize("value, expected", [("true", True), ("FALSE", False)])
def test_boolean_setting_parsing(value, expected):
    updated = update_config(AppConfig(), "debug", value)
    assert updated.debug is expected


def test_invalid_log_level_is_rejected():
    with pytest.raises(ConfigurationError, match="log_level"):
        update_config(AppConfig(), "log_level", "verbose")


def test_new_configuration_environment_variable_takes_precedence(
    tmp_path, monkeypatch
):
    legacy = tmp_path / "legacy"
    current = tmp_path / "current"
    monkeypatch.setenv("CRYPTOSUITE_CONFIG_DIR", str(legacy))
    monkeypatch.setenv("CRYPTONIK_CONFIG_DIR", str(current))
    assert config_directory() == current


def test_legacy_configuration_environment_variable_remains_supported(
    tmp_path, monkeypatch
):
    legacy = tmp_path / "legacy"
    monkeypatch.delenv("CRYPTONIK_CONFIG_DIR", raising=False)
    monkeypatch.setenv("CRYPTOSUITE_CONFIG_DIR", str(legacy))
    assert config_directory() == legacy
