"""Validated application configuration with atomic persistence."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from cryptosuite.utils.exceptions import ConfigurationError

APP_NAME = "Cryptonik"
CONFIG_ENV = "CRYPTONIK_CONFIG_DIR"
LEGACY_APP_NAME = "CryptoSuite"
LEGACY_CONFIG_ENV = "CRYPTOSUITE_CONFIG_DIR"


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Non-secret application preferences."""

    logging_enabled: bool = False
    debug: bool = False
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        allowed_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if not isinstance(self.logging_enabled, bool):
            raise ConfigurationError("logging_enabled must be true or false.")
        if not isinstance(self.debug, bool):
            raise ConfigurationError("debug must be true or false.")
        if self.log_level not in allowed_levels:
            raise ConfigurationError(
                f"log_level must be one of: {', '.join(sorted(allowed_levels))}."
            )


def config_directory() -> Path:
    """Return the configuration directory, retaining legacy discovery."""
    override = os.environ.get(CONFIG_ENV) or os.environ.get(LEGACY_CONFIG_ENV)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        target = root / APP_NAME
        legacy = root / LEGACY_APP_NAME
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        target = root / APP_NAME.lower()
        legacy = root / LEGACY_APP_NAME.lower()
    # Existing installations keep using their original directory until users
    # choose to move it. Fresh installations always use the Cryptonik path.
    if not target.exists() and legacy.exists():
        return legacy
    return target


def config_path() -> Path:
    """Return the JSON configuration file path."""
    return config_directory() / "config.json"


def load_config(path: Path | None = None) -> AppConfig:
    """Load configuration, returning secure defaults when no file exists."""
    target = path or config_path()
    if not target.exists():
        return AppConfig()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to read configuration: {target}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError("Configuration must be a JSON object.")
    known = {item.name for item in fields(AppConfig)}
    unknown = set(data) - known
    if unknown:
        raise ConfigurationError(
            f"Unknown configuration field(s): {', '.join(sorted(unknown))}."
        )
    try:
        return AppConfig(**data)
    except TypeError as exc:
        raise ConfigurationError("Configuration contains invalid fields.") from exc


def save_config(config: AppConfig, path: Path | None = None) -> Path:
    """Atomically save configuration and restrict permissions where supported."""
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{target.name}.", dir=target.parent, text=True
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(asdict(config), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        return target
    except OSError as exc:
        raise ConfigurationError(f"Unable to save configuration: {target}") from exc
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)


def update_config(config: AppConfig, key: str, value: str) -> AppConfig:
    """Return a validated copy with one CLI-provided setting changed."""
    values: dict[str, Any] = asdict(config)
    if key not in values:
        raise ConfigurationError(f"Unknown configuration field: {key}.")
    if key in {"logging_enabled", "debug"}:
        normalized = value.casefold()
        if normalized not in {"true", "false"}:
            raise ConfigurationError(f"{key} must be true or false.")
        values[key] = normalized == "true"
    else:
        values[key] = value.upper()
    return AppConfig(**values)
