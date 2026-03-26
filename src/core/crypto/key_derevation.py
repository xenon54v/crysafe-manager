from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Password policy

COMMON_WEAK_PATTERNS = {
    "password",
    "password123",
    "qwerty",
    "qwerty123",
    "123456",
    "12345678",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    ""
}


@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = 12
    require_lowercase: bool = True
    require_uppercase: bool = True
    require_digits: bool = True
    require_symbols: bool = True


@dataclass(frozen=True)
class PasswordCheckResult:
    ok: bool
    message: str


def validate_password_strength(password: str, policy: PasswordPolicy | None = None) -> PasswordCheckResult:
    policy = policy or PasswordPolicy()

    if not isinstance(password, str):
        return PasswordCheckResult(False, "Password must be a string.")

    if len(password) < policy.min_length:
        return PasswordCheckResult(False, f"Password must be at least {policy.min_length} characters long.")

    lowered = password.lower()

    if lowered in COMMON_WEAK_PATTERNS:
        return PasswordCheckResult(False, "Password is too common and easy to guess.")

    if policy.require_lowercase and not re.search(r"[a-z]", password):
        return PasswordCheckResult(False, "Password must contain at least one lowercase letter.")

    if policy.require_uppercase and not re.search(r"[A-Z]", password):
        return PasswordCheckResult(False, "Password must contain at least one uppercase letter.")

    if policy.require_digits and not re.search(r"\d", password):
        return PasswordCheckResult(False, "Password must contain at least one digit.")

    if policy.require_symbols and not re.search(r"[^A-Za-z0-9]", password):
        return PasswordCheckResult(False, "Password must contain at least one special symbol.")

    return PasswordCheckResult(True, "Password is strong enough.")

def get_password_rule_status(password: str, policy: PasswordPolicy | None = None) -> dict[str, bool]:
    policy = policy or PasswordPolicy()

    if not isinstance(password, str):
        password = ""

    lowered = password.lower()

    return {
        f"Минимум {policy.min_length} символов": len(password) >= policy.min_length,
        "Есть строчная буква": bool(re.search(r"[a-z]", password)) if policy.require_lowercase else True,
        "Есть заглавная буква": bool(re.search(r"[A-Z]", password)) if policy.require_uppercase else True,
        "Есть цифра": bool(re.search(r"\d", password)) if policy.require_digits else True,
        "Есть специальный символ": bool(re.search(r"[^A-Za-z0-9]", password)) if policy.require_symbols else True,
        "Пароль не слишком простой": lowered not in COMMON_WEAK_PATTERNS,
    }

# KDF / hashing params

@dataclass(frozen=True)
class Argon2Settings:
    time_cost: int = 3
    memory_cost: int = 65536
    parallelism: int = 4
    hash_len: int = 32
    salt_len: int = 16


@dataclass(frozen=True)
class PBKDF2Settings:
    iterations: int = 100_000
    key_length: int = 32
    salt_length: int = 16


@dataclass(frozen=True)
class AuthHashResult:
    hash: str


# Key derivation service

class KeyDerivationService:
    def __init__(
        self,
        argon2_settings: Argon2Settings | None = None,
        pbkdf2_settings: PBKDF2Settings | None = None,
    ) -> None:
        self.argon2_settings = argon2_settings or Argon2Settings()
        self.pbkdf2_settings = pbkdf2_settings or PBKDF2Settings()

        self._password_hasher = PasswordHasher(
            time_cost=self.argon2_settings.time_cost,
            memory_cost=self.argon2_settings.memory_cost,
            parallelism=self.argon2_settings.parallelism,
            hash_len=self.argon2_settings.hash_len,
            salt_len=self.argon2_settings.salt_len,
        )

    # Salt generation

    def generate_salt(self, length: int | None = None) -> bytes:
        length = length or self.pbkdf2_settings.salt_length
        return os.urandom(length)

    # Argon2 password hashing

    def create_auth_hash(self, password: str) -> AuthHashResult:
        return AuthHashResult(hash=self._password_hasher.hash(password))

    def verify_password(self, password: str, stored_hash: str) -> bool:
        try:
            return self._password_hasher.verify(stored_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            # dummy constant-time compare to reduce trivial timing distinction in failure path
            secrets.compare_digest(b"fixed_dummy_a", b"fixed_dummy_a")
            return False

    # PBKDF2 encryption key derivation

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        if not isinstance(password, str) or not password:
            raise ValueError("Password must be a non-empty string.")

        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
            raise ValueError("Salt must be at least 8 bytes.")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.pbkdf2_settings.key_length,
            salt=bytes(salt),
            iterations=self.pbkdf2_settings.iterations,
        )
        return kdf.derive(password.encode("utf-8"))