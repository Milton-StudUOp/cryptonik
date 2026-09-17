"""Tests for the Phase 1 CLI."""

import json

import pytest

from cryptosuite import __version__
from cryptosuite.cli import (
    _confirm_existing_destination,
    _default_decrypted_path,
    build_parser,
    interactive_menu,
    run_cli,
)
from cryptosuite.config import AppConfig
from cryptosuite.utils.logging_config import configure_logging


def test_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == __version__


def test_public_branding(capsys, monkeypatch):
    assert build_parser().prog == "cryptonik"
    monkeypatch.setattr("builtins.input", lambda _: "0")
    assert interactive_menu() == 0
    output = capsys.readouterr().out
    assert "CRYPTONIK" in output
    assert "CRYPTOSUITE" not in output


def test_config_show(capsys):
    assert run_cli(["config", "show"], AppConfig()) == 0
    output = capsys.readouterr().out
    document = output.split("\nConfiguration file:", maxsplit=1)[0]
    assert json.loads(document)["logging_enabled"] is False


def test_analyze_command_reports_uncertainty(capsys):
    assert run_cli(["analyze", "a" * 64], AppConfig()) == 0
    output = capsys.readouterr().out
    assert "hash/HMAC-sized value [low]" in output
    assert "cannot be reliably distinguished" in output


def test_menu_exits(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _: "0")
    assert interactive_menu() == 0
    assert "Goodbye." in capsys.readouterr().out


def test_menu_handles_invalid_choice_then_exits(monkeypatch, capsys):
    choices = iter(["invalid", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(choices))
    assert interactive_menu() == 0
    assert "Invalid selection" in capsys.readouterr().out


def test_interactive_text_encryption_is_functional(monkeypatch, capsys):
    choices = iter(["1", "1", "hello from menu", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(choices))
    monkeypatch.setattr("getpass.getpass", lambda _: "test password")
    assert interactive_menu() == 0
    output = capsys.readouterr().out
    assert "Encrypted token:" in output
    assert "use --help" not in output


def test_interactive_random_generator_is_functional(monkeypatch, capsys):
    choices = iter(["9", "1", "8", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(choices))
    assert interactive_menu() == 0
    assert "Random value:" in capsys.readouterr().out


def test_default_decrypted_path_removes_only_cryptx_suffix(tmp_path):
    assert _default_decrypted_path(tmp_path / "report.pdf.cryptx") == (
        tmp_path / "report.pdf"
    )


def test_existing_destination_requires_explicit_confirmation(tmp_path, monkeypatch):
    destination = tmp_path / "report.pdf"
    destination.write_bytes(b"original")
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    assert _confirm_existing_destination(destination) is True


def test_cli_logging_records_operation_but_not_argument_value(tmp_path, capsys):
    log = tmp_path / "operations.log"
    config = AppConfig(logging_enabled=True)
    configure_logging(config, log)
    assert run_cli(["encoding", "encode", "base64", "do-not-log-this"], config) == 0
    assert "Operation=Encoding" in log.read_text(encoding="utf-8")
    assert "do-not-log-this" not in log.read_text(encoding="utf-8")
    assert capsys.readouterr().out
