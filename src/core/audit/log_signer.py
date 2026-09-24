from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.core.clipboard.secure_memory import SecureBuffer


class AuditSigningError(RuntimeError):
    """Raised when the audit signing key cannot be used safely."""


@dataclass(frozen=True)
class AuditPublicKey:
    key_id: str
    algorithm: str
    generation: int
    public_key: bytes


class AuditLogSigner:
    """Signs audit records with a key separated from vault encryption.

    A generation-specific seed is derived through the KeyManager HKDF interface.
    Rotating generations means disclosure of the current private seed does not reveal
    private keys used for earlier generations.
    """

    ED25519 = "Ed25519"
    HMAC_SHA256 = "HMAC-SHA256"

    def __init__(
        self,
        key_manager,
        generation: int = 0,
        prefer_ed25519: bool = True,
    ) -> None:
        if generation < 0:
            raise ValueError("Signing generation must not be negative.")
        self._key_manager = key_manager
        self.generation = generation
        self.algorithm = self.ED25519 if prefer_ed25519 else self.HMAC_SHA256
        self._seed = SecureBuffer(self._derive_seed())
        self._public = self._build_public_key()
        identifier_material = (
            self.algorithm.encode("ascii")
            + generation.to_bytes(8, "big")
            + self._public
        )
        self.key_id = hashlib.sha256(identifier_material).hexdigest()

    @property
    def public_key(self) -> AuditPublicKey:
        return AuditPublicKey(
            key_id=self.key_id,
            algorithm=self.algorithm,
            generation=self.generation,
            public_key=self._public,
        )

    def sign(self, data: bytes) -> bytes:
        if not isinstance(data, bytes):
            raise TypeError("Audit data must be bytes.")
        seed = self._seed.reveal_bytes()
        try:
            if self.algorithm == self.ED25519:
                private_key = Ed25519PrivateKey.from_private_bytes(bytes(seed))
                return private_key.sign(data)
            return hmac.digest(bytes(seed), data, "sha256")
        except (TypeError, ValueError) as exc:
            raise AuditSigningError("Audit data could not be signed.") from exc
        finally:
            SecureBuffer._zero(seed)

    def verify(self, data: bytes, signature: bytes) -> bool:
        if self.algorithm == self.ED25519:
            return self.verify_ed25519(self._public, data, signature)
        seed = self._seed.reveal_bytes()
        try:
            expected = hmac.digest(bytes(seed), data, "sha256")
            return hmac.compare_digest(expected, signature)
        finally:
            SecureBuffer._zero(seed)

    def rotate(self) -> AuditLogSigner:
        next_signer = AuditLogSigner(
            self._key_manager,
            generation=self.generation + 1,
            prefer_ed25519=self.algorithm == self.ED25519,
        )
        self.clear()
        return next_signer

    def clear(self) -> None:
        self._seed.clear()

    @staticmethod
    def verify_ed25519(public_key: bytes, data: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False

    def _derive_seed(self) -> bytes:
        purpose = f"audit-signing:generation:{self.generation}"
        try:
            return self._key_manager.derive_subkey(purpose, 32)
        except (AttributeError, RuntimeError, ValueError) as exc:
            raise AuditSigningError(
                "The active master key is required for audit signing."
            ) from exc

    def _build_public_key(self) -> bytes:
        seed = self._seed.reveal_bytes()
        try:
            if self.algorithm == self.ED25519:
                private_key = Ed25519PrivateKey.from_private_bytes(bytes(seed))
                return private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            return hashlib.sha256(bytes(seed)).digest()
        finally:
            SecureBuffer._zero(seed)
