"""Centralized secret-conscious logging configuration."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptosuite.config import AppConfig, config_directory
from cryptosuite.utils.exceptions import ConfigurationError

LOGGER_NAME = "cryptonik"


def configure_logging(config: AppConfig, log_path: Path | None = None) -> logging.Logger:
    """Configure the application logger without recording secret values."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(getattr(logging, config.log_level))
    if not config.logging_enabled:
        logger.addHandler(logging.NullHandler())
        return logger

    target = log_path or config_directory() / "cryptonik.log"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(target, encoding="utf-8")
        if os.name != "nt":
            os.chmod(target, 0o600)
    except OSError as exc:
        raise ConfigurationError(f"Unable to initialize logging: {target}") from exc
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )
    logger.addHandler(handler)
    return logger


def log_operation(operation: str, algorithm: str, status: str) -> None:
    """Log only an operation's allow-listed, non-secret metadata."""
    logging.getLogger(LOGGER_NAME).info(
        "Operation=%s | Algorithm=%s | Status=%s", operation, algorithm, status
    )
