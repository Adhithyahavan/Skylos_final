"""
SecretProvider / FernetSecretProvider tests.

Covers key validation (valid, missing, invalid), encrypt/decrypt round-trip,
persistence across a simulated restart, compatibility with tokens written by
the former CredentialManager, decryption failures, fail-fast application
startup, and that key material never appears in errors, logs or stdout/stderr.
All credentials are synthetic.
"""
import logging

import pytest
from cryptography.fernet import Fernet

import config
from conftest import TEST_DB_ENCRYPTION_KEY
from secret_provider import (
    FernetSecretProvider,
    SecretDecryptionError,
    SecretProvider,
    SecretProviderConfigError,
    build_secret_provider,
    get_secret_provider,
    reset_secret_provider,
    validate_secret_provider,
)

SYNTHETIC_PASSWORD = "Synthetic-DB-Passw0rd!"


@pytest.fixture(autouse=True)
def _fresh_provider():
    reset_secret_provider()
    yield
    reset_secret_provider()


def _assert_sanitized(message: str, *secrets):
    for secret in secrets:
        if secret:
            assert secret not in message


# ── Valid key ────────────────────────────────────────────────────

def test_valid_key_builds_healthy_provider():
    provider = FernetSecretProvider(TEST_DB_ENCRYPTION_KEY)
    assert isinstance(provider, SecretProvider)
    assert provider.health_check() == {
        "provider": "fernet", "healthy": True, "detail": "encrypt/decrypt round-trip succeeded",
    }


def test_valid_key_with_surrounding_whitespace_accepted():
    provider = FernetSecretProvider(f"  {TEST_DB_ENCRYPTION_KEY}\n")
    assert provider.decrypt(provider.encrypt("x")) == "x"


def test_provider_does_not_expose_key():
    provider = FernetSecretProvider(TEST_DB_ENCRYPTION_KEY)
    assert TEST_DB_ENCRYPTION_KEY not in repr(provider)
    assert TEST_DB_ENCRYPTION_KEY not in str(provider)
    assert all(v != TEST_DB_ENCRYPTION_KEY for v in vars(provider).values())


def test_get_secret_provider_uses_settings_and_is_cached():
    first = get_secret_provider()
    assert first is get_secret_provider()
    assert first.decrypt(FernetSecretProvider(TEST_DB_ENCRYPTION_KEY).encrypt("ok")) == "ok"


# ── Missing key ──────────────────────────────────────────────────

@pytest.mark.parametrize("missing", ["", "   ", None])
def test_missing_key_is_config_error(missing):
    with pytest.raises(SecretProviderConfigError) as exc:
        FernetSecretProvider(missing)
    assert "DB_ENCRYPTION_KEY is not set" in str(exc.value)


def test_missing_key_never_falls_back_to_generated_key(monkeypatch, capfd):
    monkeypatch.setattr(config.settings, "DB_ENCRYPTION_KEY", "")
    generated = []
    monkeypatch.setattr(Fernet, "generate_key", classmethod(lambda cls: generated.append(1) or b""))
    with pytest.raises(SecretProviderConfigError):
        get_secret_provider()
    assert generated == []  # no silent key generation
    out, err = capfd.readouterr()
    assert out == "" and err == ""  # nothing printed


# ── Invalid key ──────────────────────────────────────────────────

INVALID_KEYS = [
    "not-a-valid-key",                                   # too short
    "x" * 44,                                           # right length, not base64 of 32 bytes
    "Q0hBTkdFX1RISVNfVE9fQV9TRUNVUkVfUkFORE9NX1NUUklORw==",  # base64, wrong length
    "CHANGE_THIS_TO_A_SECURE_RANDOM_STRING_AT_LEAST_32_CHARS",  # placeholder-style value
    TEST_DB_ENCRYPTION_KEY[:-2],                        # truncated real key
]


@pytest.mark.parametrize("bad_key", INVALID_KEYS)
def test_invalid_key_is_sanitized_config_error(bad_key):
    with pytest.raises(SecretProviderConfigError) as exc:
        FernetSecretProvider(bad_key)
    message = str(exc.value)
    assert "not a valid Fernet key" in message
    _assert_sanitized(message, bad_key)
    # Library exception text is not chained into the error
    assert exc.value.__cause__ is None and exc.value.__suppress_context__


def test_unsupported_provider_rejected():
    class S:
        SECRET_PROVIDER = "plaintext"
        DB_ENCRYPTION_KEY = TEST_DB_ENCRYPTION_KEY
    with pytest.raises(SecretProviderConfigError, match="Unsupported SECRET_PROVIDER"):
        build_secret_provider(S)


# ── Round-trip ───────────────────────────────────────────────────

@pytest.mark.parametrize("plaintext", [
    SYNTHETIC_PASSWORD, "", "p@ss w0rd with spaces", "ünïcødé-密码-🔐", "x" * 4096, "'; DROP TABLE users; --",
])
def test_encrypt_decrypt_round_trip(plaintext):
    provider = FernetSecretProvider(TEST_DB_ENCRYPTION_KEY)
    token = provider.encrypt(plaintext)
    assert isinstance(token, str)
    if plaintext:
        assert plaintext not in token
    assert provider.decrypt(token) == plaintext


def test_ciphertext_is_randomized():
    provider = FernetSecretProvider(TEST_DB_ENCRYPTION_KEY)
    assert provider.encrypt(SYNTHETIC_PASSWORD) != provider.encrypt(SYNTHETIC_PASSWORD)


def test_encrypt_rejects_non_string():
    with pytest.raises(TypeError):
        FernetSecretProvider(TEST_DB_ENCRYPTION_KEY).encrypt(b"bytes")


# ── Decryption failures ──────────────────────────────────────────

def test_tampered_ciphertext_rejected():
    provider = FernetSecretProvider(TEST_DB_ENCRYPTION_KEY)
    token = provider.encrypt(SYNTHETIC_PASSWORD)
    tampered = token[:-6] + ("AAAAAA" if not token.endswith("AAAAAA") else "BBBBBB")
    with pytest.raises(SecretDecryptionError):
        provider.decrypt(tampered)


@pytest.mark.parametrize("garbage", ["", "not-a-token", "gAAAA", None])
def test_garbage_ciphertext_rejected(garbage):
    with pytest.raises(SecretDecryptionError):
        FernetSecretProvider(TEST_DB_ENCRYPTION_KEY).decrypt(garbage)


# ── Restart persistence ──────────────────────────────────────────

def _store_asset(db_session, encrypted):
    from models import DatabaseAsset
    asset = DatabaseAsset(name="synthetic-pg", db_type="postgresql", host="127.0.0.1", port=5433,
                          database_name="test_company_db", username="monitor_user",
                          encrypted_password=encrypted)
    db_session.add(asset)
    db_session.commit()
    return asset.id


def test_credentials_survive_restart_with_same_key(db_session):
    from database import SessionLocal
    from models import DatabaseAsset
    from database_guardian.db_connector import create_connector

    asset_id = _store_asset(db_session, get_secret_provider().encrypt(SYNTHETIC_PASSWORD))
    stored = db_session.get(DatabaseAsset, asset_id).encrypted_password
    assert SYNTHETIC_PASSWORD not in stored  # only ciphertext is persisted

    # "Restart": drop the cached provider and read through a new session
    reset_secret_provider()
    session = SessionLocal()
    try:
        asset = session.get(DatabaseAsset, asset_id)
        assert get_secret_provider().decrypt(asset.encrypted_password) == SYNTHETIC_PASSWORD
        # Database Guardian's connector decrypts through the provider (no connection is opened here)
        assert create_connector(asset).password == SYNTHETIC_PASSWORD
    finally:
        session.close()


def test_restart_with_different_key_fails_safely(db_session, monkeypatch):
    from models import DatabaseAsset
    asset_id = _store_asset(db_session, get_secret_provider().encrypt(SYNTHETIC_PASSWORD))

    other_key = Fernet.generate_key().decode()
    monkeypatch.setattr(config.settings, "DB_ENCRYPTION_KEY", other_key)
    reset_secret_provider()
    with pytest.raises(SecretDecryptionError) as exc:
        get_secret_provider().decrypt(db_session.get(DatabaseAsset, asset_id).encrypted_password)
    _assert_sanitized(str(exc.value), other_key, TEST_DB_ENCRYPTION_KEY, SYNTHETIC_PASSWORD)
    assert "different DB_ENCRYPTION_KEY" in str(exc.value)


# ── Compatibility with the former CredentialManager ──────────────

def test_legacy_credential_manager_tokens_decrypt():
    # The old CredentialManager stored Fernet(key).encrypt(pw.encode()).decode()
    legacy_token = Fernet(TEST_DB_ENCRYPTION_KEY.encode()).encrypt(SYNTHETIC_PASSWORD.encode()).decode()
    assert FernetSecretProvider(TEST_DB_ENCRYPTION_KEY).decrypt(legacy_token) == SYNTHETIC_PASSWORD


def test_credential_manager_shim_delegates_to_provider():
    from database_guardian.credential_manager import get_credential_manager
    token = get_credential_manager().encrypt_password(SYNTHETIC_PASSWORD)
    assert get_secret_provider().decrypt(token) == SYNTHETIC_PASSWORD
    assert get_credential_manager().decrypt_password(token) == SYNTHETIC_PASSWORD


# ── Application startup ──────────────────────────────────────────

def test_validate_secret_provider_ok():
    assert validate_secret_provider().name == "fernet"


@pytest.mark.parametrize("bad_key,expected", [
    ("", "DB_ENCRYPTION_KEY is not set"),
    ("totally-invalid-key-value-12345", "not a valid Fernet key"),
])
def test_app_startup_fails_safely_on_missing_or_invalid_key(db_session, monkeypatch, caplog, capfd, bad_key, expected):
    from fastapi.testclient import TestClient
    import main

    monkeypatch.setattr(config.settings, "DB_ENCRYPTION_KEY", bad_key)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(RuntimeError) as exc:
        with TestClient(main.app):
            pass
    assert "Skylos cannot start" in str(exc.value) and expected in str(exc.value)
    out, err = capfd.readouterr()
    for text in (str(exc.value), caplog.text, out, err):
        _assert_sanitized(text, bad_key, TEST_DB_ENCRYPTION_KEY)
    assert "Configuration error" in caplog.text


def test_successful_startup_never_logs_or_prints_key(db_session, caplog, capfd):
    from fastapi.testclient import TestClient
    import main

    caplog.set_level(logging.DEBUG)
    with TestClient(main.app) as c:
        assert c.get("/api/health").status_code == 200
    out, err = capfd.readouterr()
    for text in (caplog.text, out, err):
        _assert_sanitized(text, TEST_DB_ENCRYPTION_KEY)
    assert "Secret provider ready (provider=fernet)" in caplog.text
