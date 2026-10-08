"""
Skylos — Secret Provider

Abstraction for encrypting secrets that Skylos must store and later use, such
as credentials for databases monitored by Database Guardian. Callers depend on
SecretProvider only, never on a specific cryptography library, so another
backend (HashiCorp Vault, AWS KMS, Azure Key Vault) can be added later without
touching Database Guardian code.

Rules:
  * The key is validated when the provider is built. A missing or invalid key
    is a configuration error; no key is ever generated as a fallback.
  * Keys and plaintexts are never logged, printed, or included in exception
    messages. Library exceptions are not chained (`from None`) because their
    text is outside our control.
  * Ciphertext stored by FernetSecretProvider is a standard Fernet token, the
    same format the former CredentialManager produced, so existing values
    encrypted under the configured key remain readable.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Optional

logger = logging.getLogger(__name__)

FERNET_KEY_HELP = (
    "Generate one with: python -c \"from cryptography.fernet import Fernet; "
    "print(Fernet.generate_key().decode())\" and set it as DB_ENCRYPTION_KEY in .env. "
    "Keep the same key for the lifetime of the data: credentials encrypted with a key "
    "cannot be read with a different one."
)


class SecretProviderError(Exception):
    """Base class. Messages are safe to show to operators: they never contain secrets."""


class SecretProviderConfigError(SecretProviderError):
    """The provider is not configured correctly (for example, missing or invalid key)."""


class SecretDecryptionError(SecretProviderError):
    """A stored secret could not be decrypted (wrong key, corrupted or tampered value)."""


class SecretProvider(ABC):
    """Encrypts and decrypts secrets for storage."""

    name: str = "abstract"

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Return an opaque, storable ciphertext string for `plaintext`."""

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """Return the plaintext for a value produced by `encrypt`."""

    @abstractmethod
    def health_check(self) -> Dict[str, object]:
        """Return {"provider", "healthy", "detail"}. Must not contain secret material."""

    def __repr__(self) -> str:  # never expose key material through repr/logging
        return f"<{type(self).__name__} provider={self.name}>"


class FernetSecretProvider(SecretProvider):
    """Self-hosted provider using Fernet (AES-128-CBC + HMAC-SHA256) from `cryptography`."""

    name = "fernet"
    _PROBE = "skylos-secret-provider-health-probe"

    def __init__(self, key: Optional[str]):
        from cryptography.fernet import Fernet

        key_value = (key or "").strip()
        if not key_value:
            raise SecretProviderConfigError(
                "DB_ENCRYPTION_KEY is not set. It is required to encrypt stored database "
                "credentials. " + FERNET_KEY_HELP
            )
        try:
            # Only the Fernet object is kept; the key string is not stored on self.
            self._fernet = Fernet(key_value.encode("utf-8"))
        except Exception:
            raise SecretProviderConfigError(
                "DB_ENCRYPTION_KEY is not a valid Fernet key (expected 32 url-safe "
                "base64-encoded bytes, 44 characters). " + FERNET_KEY_HELP
            ) from None

    def encrypt(self, plaintext: str) -> str:
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a string")
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        from cryptography.fernet import InvalidToken

        if not isinstance(ciphertext, str) or not ciphertext:
            raise SecretDecryptionError("Stored credential is empty or not a string.")
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError, ValueError):
            raise SecretDecryptionError(
                "Stored credential could not be decrypted: it was encrypted with a different "
                "DB_ENCRYPTION_KEY, or the stored value is corrupted."
            ) from None

    def health_check(self) -> Dict[str, object]:
        try:
            healthy = self.decrypt(self.encrypt(self._PROBE)) == self._PROBE
            detail = "encrypt/decrypt round-trip succeeded" if healthy else "round-trip mismatch"
        except SecretProviderError as e:
            healthy, detail = False, str(e)
        return {"provider": self.name, "healthy": healthy, "detail": detail}


# ── Factory / singleton ──────────────────────────────────────────

_PROVIDERS = {"fernet": lambda s: FernetSecretProvider(s.DB_ENCRYPTION_KEY)}
_provider: Optional[SecretProvider] = None


def build_secret_provider(settings) -> SecretProvider:
    """Build the provider selected by settings.SECRET_PROVIDER (default: fernet)."""
    provider_name = (getattr(settings, "SECRET_PROVIDER", "fernet") or "fernet").strip().lower()
    factory = _PROVIDERS.get(provider_name)
    if factory is None:
        raise SecretProviderConfigError(
            f"Unsupported SECRET_PROVIDER {provider_name!r}. Supported: {', '.join(sorted(_PROVIDERS))}."
        )
    return factory(settings)


def get_secret_provider() -> SecretProvider:
    """Return the process-wide provider, building and validating it on first use."""
    global _provider
    if _provider is None:
        from config import settings
        _provider = build_secret_provider(settings)
    return _provider


def reset_secret_provider() -> None:
    """Forget the cached provider (tests, or after configuration changes)."""
    global _provider
    _provider = None


def validate_secret_provider() -> SecretProvider:
    """
    Startup check: build the provider and run its health check.
    Raises SecretProviderConfigError with a sanitized message on failure.
    """
    provider = get_secret_provider()
    health = provider.health_check()
    if not health["healthy"]:
        reset_secret_provider()
        raise SecretProviderConfigError(f"Secret provider health check failed: {health['detail']}")
    logger.info("Secret provider ready (provider=%s)", provider.name)
    return provider
