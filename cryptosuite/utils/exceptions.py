"""Public exception hierarchy for safe user-facing failures."""


class CryptoSuiteError(Exception):
    """Base class for expected, user-facing Cryptonik failures."""


class ConfigurationError(CryptoSuiteError):
    """Raised when application configuration is invalid or unavailable."""


class ValidationError(CryptoSuiteError):
    """Raised when user-controlled input fails validation."""


class AuthenticationError(CryptoSuiteError):
    """Raised when encrypted or authenticated data cannot be verified."""


class UnsupportedAlgorithmError(CryptoSuiteError):
    """Raised when an algorithm identifier is not supported."""


class FileFormatError(CryptoSuiteError):
    """Raised when a cryptographic container is malformed or unsupported."""


class KeyManagementError(CryptoSuiteError):
    """Raised when a key operation cannot be completed safely."""


class VaultError(CryptoSuiteError):
    """Raised when an encrypted vault operation fails."""
