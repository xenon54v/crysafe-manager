from __future__ import annotations

import os
import re
from dataclasses import dataclass
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError
from hashlib import pbkdf2_hmac

# Password Policy

COMMON_WEAK_PATTERNS = {
    "password!",
    "password0!",
    "password1!",
    "password123!",
    "qwerty123456!",
    "12345678!",
    "1234567890!",
    "0987654321!",
    "qwerty111!",
    "qwerty123!",
    "admin000!",
    "admin123!",
    "myadmin1!",
    "loginlogin!",
    ""
}
COMMON_WEAK_SUBSTRINGS = [
    "password",
    "qwerty",
    "123456",
    "admin",
    "login",
]

@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_symbols: bool = True

@dataclass(frozen=True)
class PasswordValidationResult:
    ok: bool
    message: str

def validate_password(password: str, policy: PasswordPolicy | None = None) -> PasswordValidationResult:
    policy = policy or PasswordPolicy()

    if not isinstance(password, str) or not password:
        return PasswordValidationResult(False, "Пароль не может быть пустым")

    if len(password) < policy.min_length:
        return PasswordValidationResult(False, f"Пароль должен быть не короче {policy.min_length} символов")

    if policy.require_uppercase and not re.search(r"[A-Z]", password):
        return PasswordValidationResult(False, "Добавьте хотя бы одну заглавную букву")

    if policy.require_lowercase and not re.search(r"[a-z]", password):
        return PasswordValidationResult(False, "Добавьте хотя бы одну строчную букву")

    if policy.require_digits and not re.search(r"\d", password):
        return PasswordValidationResult(False, "Добавьте хотя бы одну цифру")

    if policy.require_symbols and not re.search(r"[^A-Za-z0-9]", password):
        return PasswordValidationResult(False, "Добавьте хотя бы один специальный символ")

    lowered = password.lower()

    if lowered in COMMON_WEAK_PATTERNS:
        return PasswordValidationResult(False, "Слишком простой пароль.")

    if any(part in lowered for part in COMMON_WEAK_SUBSTRINGS):
        return PasswordValidationResult(False, "Пароль содержит слишком простой шаблон.")

    return PasswordValidationResult(True, "OK")

# Auth Hash

@dataclass(frozen=True)
class AuthHashResult:
    hash: str

@dataclass(frozen=True)
class Argon2Settings:
    time_cost: int = 3
    memory_cost: int = 65536
    parallelism: int = 4
    hash_len: int = 32

# Key Derivation

class KeyDerivationService:

    def __init__(self, settings: Argon2Settings | None = None) -> None:
        self.settings = settings or Argon2Settings()

        self._hasher = PasswordHasher(
            time_cost=self.settings.time_cost,
            memory_cost=self.settings.memory_cost,
            parallelism=self.settings.parallelism,
            hash_len=self.settings.hash_len,
            type=Type.ID,
        )

    # Argon2 (auth)

    def create_auth_hash(self, password: str) -> AuthHashResult:
        hash_value = self._hasher.hash(password)
        return AuthHashResult(hash=hash_value)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        try:
            return self._hasher.verify(stored_hash, password)
        except VerifyMismatchError:
            return False

    # PBKDF2 (encryption key)

    def generate_salt(self, length: int = 16) -> bytes:
        return os.urandom(length)

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        return pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            200_000,
            dklen=32,
        )

# UI Helper

def get_password_rule_status(password: str, policy: PasswordPolicy | None = None) -> dict[str, bool]:
    policy = policy or PasswordPolicy()

    if not isinstance(password, str):
        password = ""

    lowered = password.lower()

    return {
        f"Минимум {policy.min_length} символов": len(password) >= policy.min_length,
        "Есть строчная буква": bool(re.search(r"[a-z]", password)),
        "Есть заглавная буква": bool(re.search(r"[A-Z]", password)),
        "Есть цифра": bool(re.search(r"\d", password)),
        "Есть специальный символ": bool(re.search(r"[^A-Za-z0-9]", password)),
        "Пароль не слишком простой": (
    lowered not in COMMON_WEAK_PATTERNS
    and not any(part in lowered for part in COMMON_WEAK_SUBSTRINGS)
),
    }