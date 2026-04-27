from src.core.crypto.key_derivation import (
    KeyDerivationService,
    validate_password,
    get_password_rule_status,
)

def test_password_validation_ok():
    result = validate_password("StrongPass123!")

    assert result.ok is True

def test_password_validation_rejects_short_password():
    result = validate_password("Aa1!")

    assert result.ok is False

def test_password_validation_rejects_weak_pattern():
    result = validate_password("Password123!")

    assert result.ok is False

def test_auth_hash_verify_success():
    service = KeyDerivationService()

    auth_hash = service.create_auth_hash("StrongPass123!").hash

    assert service.verify_password("StrongPass123!", auth_hash) is True

def test_auth_hash_verify_wrong_password():
    service = KeyDerivationService()

    auth_hash = service.create_auth_hash("StrongPass123!").hash

    assert service.verify_password("WrongPass123!", auth_hash) is False

def test_pbkdf2_key_is_32_bytes():
    service = KeyDerivationService()

    salt = service.generate_salt()
    key = service.derive_encryption_key("StrongPass123!", salt)

    assert isinstance(key, bytes)
    assert len(key) == 32

def test_password_rule_status():
    status = get_password_rule_status("StrongPass123!")

    assert status["Минимум 12 символов"] is True
    assert status["Есть строчная буква"] is True
    assert status["Есть заглавная буква"] is True
    assert status["Есть цифра"] is True
    assert status["Есть специальный символ"] is True