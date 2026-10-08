"""
Credential Manager - deprecated compatibility shim.

Database Guardian credentials are encrypted through secret_provider.SecretProvider.
This module no longer holds keys or touches Fernet; it only delegates, so older
imports keep working. New code should call get_secret_provider() directly.
"""
from secret_provider import get_secret_provider


class CredentialManager:
    def encrypt_password(self, password: str) -> str:
        return get_secret_provider().encrypt(password)

    def decrypt_password(self, encrypted: str) -> str:
        return get_secret_provider().decrypt(encrypted)


def get_credential_manager() -> CredentialManager:
    return CredentialManager()
