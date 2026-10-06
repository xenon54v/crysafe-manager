from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .errors import ImportValidationError

PBKDF2_ITERATIONS = 100_000


def canonical_json(value: Any) -> bytes:
    """Serialize a value as deterministic UTF-8 JSON bytes."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def b64encode(value: bytes) -> str:
    """Encode bytes as URL-safe Base64 text."""

    return base64.b64encode(value).decode("ascii")


def b64decode(value: str, field: str) -> bytes:
    """Decode URL-safe Base64 text."""

    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ImportValidationError(f"Invalid base64 value in {field}.") from exc


def clear_bytes(value: bytearray | None) -> None:
    """Overwrite and release a mutable byte buffer."""

    if value is not None:
        for index in range(len(value)):
            value[index] = 0


def derive_password_key(
    password: str,
    salt: bytes,
    *,
    key_size: int = 32,
    iterations: int = PBKDF2_ITERATIONS,
) -> bytes:
    """Derive an encryption key from a password and salt."""

    if not password:
        raise ValueError("Encryption password must not be empty.")
    if key_size not in {16, 32}:
        raise ValueError("AES key size must be 128 or 256 bits.")
    if not PBKDF2_ITERATIONS <= iterations <= 5_000_000:
        raise ValueError("PBKDF2 iterations must be between 100,000 and 5,000,000.")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=iterations,
    ).derive(password.encode("utf-8"))


def _mac_key(key: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"CryptoSafe Manager exchange integrity v1",
    ).derive(key)


def encrypt_payload_with_password(
    plaintext: bytes,
    password: str,
    *,
    key_size: int = 32,
    associated_data: bytes = b"",
) -> dict[str, Any]:
    """Encrypt a payload with a password-derived key."""

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key_buffer = bytearray(derive_password_key(password, salt, key_size=key_size))
    try:
        ciphertext = AESGCM(bytes(key_buffer)).encrypt(
            nonce, plaintext, associated_data or None
        )
        signature = hmac.new(
            _mac_key(bytes(key_buffer)), associated_data + ciphertext, hashlib.sha256
        ).digest()
        return {
            "encryption": {
                "algorithm": f"AES-{key_size * 8}-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA256",
                "iterations": PBKDF2_ITERATIONS,
                "salt": b64encode(salt),
                "nonce": b64encode(nonce),
            },
            "data": b64encode(ciphertext),
            "integrity": {
                "hash_algorithm": "SHA-256",
                "hash": hashlib.sha256(ciphertext).hexdigest(),
                "signature_algorithm": "HMAC-SHA256",
                "signature": b64encode(signature),
            },
        }
    finally:
        clear_bytes(key_buffer)


def decrypt_payload_with_password(
    package: dict[str, Any],
    password: str,
    *,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt and authenticate a password-protected payload."""

    encryption = _mapping(package, "encryption")
    integrity = _mapping(package, "integrity")
    algorithm = str(encryption.get("algorithm", ""))
    key_size = {"AES-128-GCM": 16, "AES-256-GCM": 32}.get(algorithm)
    if key_size is None:
        raise ImportValidationError("Unsupported password encryption algorithm.")
    iterations = int(encryption.get("iterations", 0))
    salt = b64decode(str(encryption.get("salt", "")), "encryption.salt")
    nonce = b64decode(str(encryption.get("nonce", "")), "encryption.nonce")
    ciphertext = b64decode(str(package.get("data", "")), "data")
    if len(nonce) != 12 or len(salt) < 16:
        raise ImportValidationError("Invalid encryption parameters.")
    if not hmac.compare_digest(
        hashlib.sha256(ciphertext).hexdigest(), str(integrity.get("hash", ""))
    ):
        raise ImportValidationError("Encrypted data checksum verification failed.")

    try:
        key_buffer = bytearray(
            derive_password_key(
                password, salt, key_size=key_size, iterations=iterations
            )
        )
    except ValueError as exc:
        raise ImportValidationError("Invalid password derivation parameters.") from exc
    try:
        expected = hmac.new(
            _mac_key(bytes(key_buffer)), associated_data + ciphertext, hashlib.sha256
        ).digest()
        actual = b64decode(str(integrity.get("signature", "")), "integrity.signature")
        if not hmac.compare_digest(expected, actual):
            raise ImportValidationError("Package signature verification failed.")
        try:
            return AESGCM(bytes(key_buffer)).decrypt(
                nonce, ciphertext, associated_data or None
            )
        except Exception as exc:
            raise ImportValidationError("Package decryption failed.") from exc
    finally:
        clear_bytes(key_buffer)


def encrypt_payload_with_public_key(
    plaintext: bytes,
    public_key_pem: bytes,
    *,
    associated_data: bytes = b"",
    sender_public_key: bytes | None = None,
) -> dict[str, Any]:
    """Encrypt a payload for an RSA or elliptic-curve recipient."""

    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as exc:
        raise ValueError("Recipient public key is invalid.") from exc

    content_key = bytearray(os.urandom(32))
    nonce = os.urandom(12)
    ephemeral_public = None
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            raise ValueError("RSA public key must contain at least 2048 bits.")
        wrapped_key = public_key.encrypt(
            bytes(content_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        algorithm = "RSA-OAEP-SHA256/AES-256-GCM"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise TypeError("Only the P-256 elliptic curve is supported.")
        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=nonce,
            info=b"CryptoSafe Manager ECIES P-256 v1",
        ).derive(shared_secret)
        clear_bytes(content_key)
        content_key = bytearray(derived)
        wrapped_key = b""
        ephemeral_public = ephemeral_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        algorithm = "ECDH-P256-HKDF-SHA256/AES-256-GCM"
    else:
        raise TypeError("Only RSA-2048+ and ECC P-256 public keys are supported.")

    try:
        ciphertext = AESGCM(bytes(content_key)).encrypt(
            nonce, plaintext, associated_data or None
        )
        signature = hmac.new(
            _mac_key(bytes(content_key)), associated_data + ciphertext, hashlib.sha256
        ).digest()
        result: dict[str, Any] = {
            "encryption": {
                "algorithm": algorithm,
                "nonce": b64encode(nonce),
            },
            "encrypted_key": b64encode(wrapped_key),
            "data": b64encode(ciphertext),
            "integrity": {
                "hash_algorithm": "SHA-256",
                "hash": hashlib.sha256(ciphertext).hexdigest(),
                "signature_algorithm": "HMAC-SHA256",
                "signature": b64encode(signature),
            },
        }
        if ephemeral_public is not None:
            result["encryption"]["ephemeral_public_key"] = b64encode(ephemeral_public)
        if sender_public_key is not None:
            result["sender_public_key"] = b64encode(sender_public_key)
        return result
    finally:
        clear_bytes(content_key)


def decrypt_payload_with_private_key(
    package: dict[str, Any],
    private_key_pem: bytes,
    *,
    private_key_password: bytes | None = None,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt a payload with the matching private key."""

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=private_key_password
        )
    except (TypeError, ValueError) as exc:
        raise ImportValidationError("Recipient private key is invalid.") from exc

    encryption = _mapping(package, "encryption")
    integrity = _mapping(package, "integrity")
    algorithm = str(encryption.get("algorithm", ""))
    nonce = b64decode(str(encryption.get("nonce", "")), "encryption.nonce")
    ciphertext = b64decode(str(package.get("data", "")), "data")
    if len(nonce) != 12:
        raise ImportValidationError("Invalid encryption nonce.")
    if not hmac.compare_digest(
        hashlib.sha256(ciphertext).hexdigest(), str(integrity.get("hash", ""))
    ):
        raise ImportValidationError("Encrypted data checksum verification failed.")

    if algorithm == "RSA-OAEP-SHA256/AES-256-GCM" and isinstance(
        private_key, rsa.RSAPrivateKey
    ):
        wrapped = b64decode(str(package.get("encrypted_key", "")), "encrypted_key")
        try:
            content_key_value = private_key.decrypt(
                wrapped,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise ImportValidationError("Unable to unwrap the package key.") from exc
    elif algorithm == "ECDH-P256-HKDF-SHA256/AES-256-GCM" and isinstance(
        private_key, ec.EllipticCurvePrivateKey
    ):
        ephemeral_pem = b64decode(
            str(encryption.get("ephemeral_public_key", "")),
            "encryption.ephemeral_public_key",
        )
        try:
            ephemeral = serialization.load_pem_public_key(ephemeral_pem)
            if not isinstance(ephemeral, ec.EllipticCurvePublicKey):
                raise TypeError
            shared_secret = private_key.exchange(ec.ECDH(), ephemeral)
            content_key_value = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=nonce,
                info=b"CryptoSafe Manager ECIES P-256 v1",
            ).derive(shared_secret)
        except (TypeError, ValueError) as exc:
            raise ImportValidationError("Invalid ephemeral public key.") from exc
    else:
        raise ImportValidationError("Private key does not match the package algorithm.")

    content_key = bytearray(content_key_value)
    try:
        expected = hmac.new(
            _mac_key(bytes(content_key)), associated_data + ciphertext, hashlib.sha256
        ).digest()
        actual = b64decode(str(integrity.get("signature", "")), "integrity.signature")
        if not hmac.compare_digest(expected, actual):
            raise ImportValidationError("Package signature verification failed.")
        try:
            return AESGCM(bytes(content_key)).decrypt(
                nonce, ciphertext, associated_data or None
            )
        except Exception as exc:
            raise ImportValidationError("Package decryption failed.") from exc
    finally:
        clear_bytes(content_key)


def _mapping(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = value.get(field)
    if not isinstance(result, dict):
        raise ImportValidationError(f"Missing or invalid {field} section.")
    return result
