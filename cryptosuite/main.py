"""Cryptonik application entry point."""

from __future__ import annotations

import sys
import traceback

from cryptosuite.cli import run_cli
from cryptosuite.config import load_config
from cryptosuite.utils.exceptions import CryptoSuiteError
from cryptosuite.utils.logging_config import configure_logging


def main(argv: list[str] | None = None) -> int:
    """Run Cryptonik and translate expected failures into safe messages."""
    try:
        config = load_config()
        configure_logging(config)
        return run_cli(argv, config)
    except CryptoSuiteError as exc:
        print(f"ERROR\n\n{exc}", file=sys.stderr)
        if _debug_enabled():
            traceback.print_exc()
        return 2
    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        return 130
    except Exception:  # noqa: BLE001 - application boundary hides unsafe tracebacks
        print(
            "ERROR\n\nAn unexpected error occurred. No output was committed.",
            file=sys.stderr,
        )
        if _debug_enabled():
            traceback.print_exc()
        return 1


def _debug_enabled() -> bool:
    """Best-effort debug lookup that cannot mask an original error."""
    try:
        return load_config().debug
    except CryptoSuiteError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
