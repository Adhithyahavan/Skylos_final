"""Guards against shipping usable secrets in files that are meant to be copied."""
import os

import pytest
from cryptography.fernet import Fernet

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _env_example():
    values = {}
    with open(os.path.join(ROOT, ".env.example"), encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key] = value
    return values


def test_env_example_ships_no_usable_encryption_key():
    value = _env_example()["DB_ENCRYPTION_KEY"]
    with pytest.raises(Exception):
        Fernet(value.encode())   # a placeholder, not a working key anyone could reuse


@pytest.mark.parametrize("name", ["JWT_SECRET_KEY", "AGENT_API_KEY", "POSTGRES_PASSWORD"])
def test_env_example_secrets_are_placeholders(name):
    assert _env_example()[name].startswith("CHANGE_THIS")


@pytest.mark.parametrize("name", ["SKYLOS_BOOTSTRAP_ADMIN_PASSWORD", "GUARDIAN_TEST_DB_PASSWORD", "SMTP_PASSWORD"])
def test_env_example_has_no_real_passwords(name):
    value = _env_example()[name]
    assert value == "" or "your-" in value or value.startswith("CHANGE_THIS")
