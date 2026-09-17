"""Tests for safe logging setup."""

from cryptosuite.config import AppConfig
from cryptosuite.utils.logging_config import configure_logging, log_operation


def test_logging_disabled_does_not_create_file(tmp_path):
    target = tmp_path / "cryptosuite.log"
    configure_logging(AppConfig(), target)
    log_operation("Hash File", "SHA-256", "Success")
    assert not target.exists()


def test_logging_records_only_passed_metadata(tmp_path):
    target = tmp_path / "cryptosuite.log"
    configure_logging(AppConfig(logging_enabled=True), target)
    log_operation("Hash File", "SHA-256", "Success")
    content = target.read_text(encoding="utf-8")
    assert "Operation=Hash File" in content
    assert "Algorithm=SHA-256" in content
    assert "Status=Success" in content
