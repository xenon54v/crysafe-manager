from __future__ import annotations

import base64
import hashlib
import io
import json
import secrets
import time
import uuid
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from src.database.exchange_repo import ExchangeRepository

from .errors import QRCodeError


@dataclass(frozen=True)
class KeyPair:
    """Represent key pair behavior."""

    algorithm: str
    private_key: bytes
    public_key: bytes
    fingerprint: str


@dataclass(frozen=True)
class QRPayload:
    """Describe a validated QR exchange payload."""

    payload_type: str
    data: bytes
    created_at: str
    expires_at: str
    nonce: str
    checksum: str


class KeyExchangeService:
    """Manages public contact keys without storing recipient private keys."""

    def __init__(self, db=None, audit_logger=None) -> None:
        self.db = db
        self.audit_logger = audit_logger

    def generate_key_pair(
        self,
        algorithm: str = "ECC-P256",
        *,
        private_key_password: bytes | None = None,
    ) -> KeyPair:
        normalized = algorithm.upper().replace("_", "-")
        if normalized in {"RSA", "RSA-2048"}:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            algorithm_name = "RSA-2048"
        elif normalized in {"ECC", "ECC-P256", "P-256"}:
            private_key = ec.generate_private_key(ec.SECP256R1())
            algorithm_name = "ECC-P256"
        else:
            raise ValueError("Key algorithm must be RSA-2048 or ECC-P256.")
        encryption = (
            serialization.BestAvailableEncryption(private_key_password)
            if private_key_password
            else serialization.NoEncryption()
        )
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return KeyPair(
            algorithm=algorithm_name,
            private_key=private_pem,
            public_key=public_pem,
            fingerprint=self.fingerprint(public_pem),
        )

    def add_contact(
        self,
        name: str,
        identifier: str,
        public_key: bytes,
        *,
        verified: bool = False,
    ) -> str:
        if self.db is None:
            raise RuntimeError("A database is required for contact storage.")
        name = name.strip()
        identifier = identifier.strip()
        if not name or not identifier:
            raise ValueError("Contact name and identifier are required.")
        algorithm = self._key_algorithm(public_key)
        fingerprint = self.fingerprint(public_key)
        contact_id = str(uuid.uuid4())
        key_id = str(uuid.uuid4())
        now = self._now()
        with self.db.transaction(write=True):
            self.db.execute(
                """
                INSERT INTO contacts (
                    contact_id, name, identifier, algorithm, public_key,
                    fingerprint, verified, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    contact_id,
                    name,
                    identifier,
                    algorithm,
                    public_key,
                    fingerprint,
                    int(verified),
                    now,
                    now,
                ),
            )
            self.db.execute(
                """
                INSERT INTO contact_keys (
                    key_id, contact_id, algorithm, public_key,
                    fingerprint, created_at
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (key_id, contact_id, algorithm, public_key, fingerprint, now),
            )
        self._audit(
            "CONTACT_KEY_ADDED", {"contact_id": contact_id, "algorithm": algorithm}
        )
        return contact_id

    def verify_contact_fingerprint(self, contact_id: str, fingerprint: str) -> bool:
        row = self._contact(contact_id)
        expected = str(row["fingerprint"])
        verified = secrets.compare_digest(
            self.normalize_fingerprint(expected),
            self.normalize_fingerprint(fingerprint),
        )
        if verified:
            self.db.execute(
                "UPDATE contacts SET verified = 1, updated_at = ? WHERE contact_id = ?;",
                (self._now(), contact_id),
            )
            self._audit("CONTACT_KEY_VERIFIED", {"contact_id": contact_id})
        return verified

    def rotate_contact_key(self, contact_id: str, new_public_key: bytes) -> str:
        self._contact(contact_id)
        algorithm = self._key_algorithm(new_public_key)
        fingerprint = self.fingerprint(new_public_key)
        now = self._now()
        key_id = str(uuid.uuid4())
        with self.db.transaction(write=True):
            self.db.execute(
                "UPDATE contact_keys SET revoked_at = ? WHERE contact_id = ? AND revoked_at IS NULL;",
                (now, contact_id),
            )
            self.db.execute(
                """
                INSERT INTO contact_keys (
                    key_id, contact_id, algorithm, public_key,
                    fingerprint, created_at
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (key_id, contact_id, algorithm, new_public_key, fingerprint, now),
            )
            self.db.execute(
                """
                UPDATE contacts
                SET algorithm = ?, public_key = ?, fingerprint = ?,
                    verified = 0, revoked_at = NULL, updated_at = ?
                WHERE contact_id = ?;
                """,
                (algorithm, new_public_key, fingerprint, now, contact_id),
            )
        self._audit(
            "CONTACT_KEY_ROTATED", {"contact_id": contact_id, "algorithm": algorithm}
        )
        return fingerprint

    def revoke_contact_key(self, contact_id: str) -> None:
        self._contact(contact_id)
        now = self._now()
        with self.db.transaction(write=True):
            self.db.execute(
                "UPDATE contacts SET revoked_at = ?, updated_at = ? WHERE contact_id = ?;",
                (now, now, contact_id),
            )
            self.db.execute(
                "UPDATE contact_keys SET revoked_at = ? WHERE contact_id = ? AND revoked_at IS NULL;",
                (now, contact_id),
            )
        self._audit("CONTACT_KEY_REVOKED", {"contact_id": contact_id})

    def get_contact_public_key(self, contact_id: str) -> bytes:
        row = self._contact(contact_id)
        if row["revoked_at"]:
            raise ValueError("The contact key has been revoked.")
        self.db.execute(
            "UPDATE contacts SET last_used_at = ? WHERE contact_id = ?;",
            (self._now(), contact_id),
        )
        return bytes(row["public_key"])

    def list_contacts(self, *, include_revoked: bool = False) -> list[dict[str, Any]]:
        if self.db is None:
            return []
        where = "" if include_revoked else " WHERE revoked_at IS NULL"
        rows = self.db.execute(
            "SELECT * FROM contacts" + where + " ORDER BY name COLLATE NOCASE;"
        ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def fingerprint(public_key: bytes) -> str:
        try:
            key = serialization.load_pem_public_key(public_key)
        except (TypeError, ValueError) as exc:
            raise ValueError("Public key is invalid.") from exc
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(der).hexdigest().upper()
        return ":".join(digest[index : index + 4] for index in range(0, len(digest), 4))

    @staticmethod
    def normalize_fingerprint(value: str) -> str:
        return "".join(
            character for character in value.upper() if character in "0123456789ABCDEF"
        )

    @staticmethod
    def _key_algorithm(public_key: bytes) -> str:
        try:
            key = serialization.load_pem_public_key(public_key)
        except (TypeError, ValueError) as exc:
            raise ValueError("Public key is invalid.") from exc
        if isinstance(key, rsa.RSAPublicKey):
            if key.key_size < 2048:
                raise ValueError("RSA public key must contain at least 2048 bits.")
            return f"RSA-{key.key_size}"
        if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(
            key.curve, ec.SECP256R1
        ):
            return "ECC-P256"
        raise ValueError("Only RSA-2048+ and ECC P-256 public keys are supported.")

    def _contact(self, contact_id: str):
        if self.db is None:
            raise RuntimeError("A database is required for contact storage.")
        row = self.db.execute(
            "SELECT * FROM contacts WHERE contact_id = ?;", (contact_id,)
        ).fetchone()
        if row is None:
            raise ValueError("Contact was not found.")
        return row

    def _audit(self, event: str, details: dict[str, Any]) -> None:
        if self.audit_logger is not None:
            self.audit_logger.log_event(
                event,
                severity="INFO",
                source="key_exchange",
                details=details,
                user_id="local_user",
            )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()


class QRCodeService:
    """Create, split, validate, and reconstruct QR payloads."""

    ALLOWED_TYPES: ClassVar[set[str]] = {
        "public_key",
        "encrypted_entry",
        "share_link",
    }

    def __init__(self, db=None, *, default_validity_seconds: int = 300) -> None:
        if not 30 <= default_validity_seconds <= 1800:
            raise ValueError("QR validity must be between 30 seconds and 30 minutes.")
        self.db = db
        self.default_validity_seconds = default_validity_seconds
        self.repository = ExchangeRepository(db) if db is not None else None
        self._used_nonces: set[str] = set()

    def create_payload(
        self,
        payload_type: str,
        data: bytes | str,
        *,
        validity_seconds: int | None = None,
    ) -> bytes:
        if payload_type not in self.ALLOWED_TYPES:
            raise QRCodeError("Unsupported QR payload type.")
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        self._validate_safe_payload(payload_type, raw)
        validity = validity_seconds or self.default_validity_seconds
        if not 30 <= validity <= 1800:
            raise QRCodeError("QR validity must be between 30 seconds and 30 minutes.")
        now = datetime.now(timezone.utc)
        envelope = {
            "version": 1,
            "payload_type": payload_type,
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=validity)).isoformat(),
            "nonce": secrets.token_urlsafe(18),
            "data": base64.b64encode(raw).decode("ascii"),
            "checksum": hashlib.sha256(raw).hexdigest(),
        }
        return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    def encode_chunks(self, envelope: bytes, *, chunk_size: int = 1800) -> list[str]:
        if not 256 <= chunk_size <= 2200:
            raise ValueError("QR chunk size must be between 256 and 2200 bytes.")
        compressed = zlib.compress(envelope, level=6)
        encoded = base64.b64encode(compressed).decode("ascii")
        total = max(1, (len(encoded) + chunk_size - 1) // chunk_size)
        if total > 100:
            raise QRCodeError("QR payload requires too many chunks.")
        envelope_id = hashlib.sha256(envelope).hexdigest()[:20]
        result = []
        for index in range(total):
            part = encoded[index * chunk_size : (index + 1) * chunk_size]
            result.append(
                json.dumps(
                    {
                        "csm_qr": 1,
                        "id": envelope_id,
                        "index": index + 1,
                        "total": total,
                        "data": part,
                        "checksum": hashlib.sha256(part.encode("ascii")).hexdigest()[
                            :16
                        ],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        return result

    def generate_qr_codes(
        self,
        envelope: bytes,
        *,
        chunk_size: int = 1800,
        box_size: int = 8,
    ) -> list[bytes]:
        images = []
        for chunk in self.encode_chunks(envelope, chunk_size=chunk_size):
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=box_size,
                border=4,
            )
            qr.add_data(chunk, optimize=20)
            qr.make(fit=True)
            stream = io.BytesIO()
            qr.make_image(fill_color="black", back_color="white").save(
                stream, format="PNG"
            )
            images.append(stream.getvalue())
        return images

    def decode_chunks(self, chunks: list[str], *, mark_used: bool = True) -> QRPayload:
        if not chunks:
            raise QRCodeError("No QR chunks were provided.")
        decoded: dict[int, str] = {}
        envelope_id = ""
        total = 0
        for chunk_text in chunks:
            try:
                chunk = json.loads(chunk_text)
                if chunk.get("csm_qr") != 1:
                    raise ValueError
                current_id = str(chunk["id"])
                current_total = int(chunk["total"])
                index = int(chunk["index"])
                data = str(chunk["data"])
                checksum = str(chunk["checksum"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise QRCodeError("A QR chunk is malformed.") from exc
            if not secrets.compare_digest(
                hashlib.sha256(data.encode("ascii")).hexdigest()[:16], checksum
            ):
                raise QRCodeError("QR chunk checksum verification failed.")
            if not envelope_id:
                envelope_id, total = current_id, current_total
            if (
                current_id != envelope_id
                or current_total != total
                or not 1 <= index <= total
            ):
                raise QRCodeError("QR chunks belong to different payloads.")
            if index in decoded and decoded[index] != data:
                raise QRCodeError("Conflicting duplicate QR chunk detected.")
            decoded[index] = data
        if total < 1 or set(decoded) != set(range(1, total + 1)):
            raise QRCodeError("QR payload is incomplete.")
        try:
            compressed = base64.b64decode(
                "".join(decoded[index] for index in range(1, total + 1)), validate=True
            )
            envelope_bytes = zlib.decompress(compressed)
            if hashlib.sha256(envelope_bytes).hexdigest()[:20] != envelope_id:
                raise QRCodeError("QR payload checksum verification failed.")
            envelope = json.loads(envelope_bytes.decode("utf-8"))
            raw = base64.b64decode(str(envelope["data"]), validate=True)
        except QRCodeError:
            raise
        except Exception as exc:
            raise QRCodeError("QR payload could not be decoded.") from exc
        if envelope.get("payload_type") not in self.ALLOWED_TYPES:
            raise QRCodeError("QR payload type is unsupported.")
        if not secrets.compare_digest(
            hashlib.sha256(raw).hexdigest(), str(envelope.get("checksum", ""))
        ):
            raise QRCodeError("QR payload integrity verification failed.")
        try:
            expires = datetime.fromisoformat(str(envelope["expires_at"]))
        except (KeyError, ValueError) as exc:
            raise QRCodeError("QR expiration timestamp is invalid.") from exc
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            raise QRCodeError("QR payload has expired.")
        nonce = str(envelope.get("nonce", ""))
        if not nonce:
            raise QRCodeError("QR replay nonce is missing.")
        if mark_used and not self._mark_nonce(nonce, expires.isoformat()):
            raise QRCodeError("QR payload has already been used.")
        self._validate_safe_payload(str(envelope["payload_type"]), raw)
        return QRPayload(
            payload_type=str(envelope["payload_type"]),
            data=raw,
            created_at=str(envelope["created_at"]),
            expires_at=expires.isoformat(),
            nonce=nonce,
            checksum=str(envelope["checksum"]),
        )

    def scan_image(self, path: Path | str) -> str:
        try:
            import zxingcpp
            from PIL import Image

            result = zxingcpp.read_barcode(Image.open(path))
            if result is not None and result.text:
                return result.text
        except (ImportError, OSError, ValueError):
            pass
        try:
            import cv2
        except ImportError as exc:
            raise QRCodeError("Image scanning support is not installed.") from exc
        image = cv2.imread(str(path))
        if image is None:
            raise QRCodeError("QR image could not be opened.")
        data, _points, _straight = cv2.QRCodeDetector().detectAndDecode(image)
        if not data:
            raise QRCodeError("No readable QR code was found in the image.")
        return data

    def scan_camera(
        self, *, camera_index: int = 0, timeout_seconds: float = 10.0
    ) -> str:
        try:
            import cv2
        except ImportError as exc:
            raise QRCodeError("Camera scanning support is not installed.") from exc
        capture = cv2.VideoCapture(camera_index)
        if not capture.isOpened():
            capture.release()
            raise QRCodeError("No available camera was found.")
        detector = cv2.QRCodeDetector()
        deadline = time.monotonic() + max(1.0, min(timeout_seconds, 30.0))
        try:
            while time.monotonic() < deadline:
                ok, frame = capture.read()
                if not ok:
                    continue
                data = ""
                try:
                    import zxingcpp

                    result = zxingcpp.read_barcode(frame)
                    if result is not None:
                        data = result.text
                except ImportError:
                    pass
                if not data:
                    data, _points, _straight = detector.detectAndDecode(frame)
                if data:
                    return data
        finally:
            capture.release()
        raise QRCodeError("Camera scan timed out without a readable QR code.")

    def scan_clipboard_image(self) -> str:
        try:
            import zxingcpp
            from PIL import Image, ImageGrab

            clipboard_value = ImageGrab.grabclipboard()
        except (ImportError, OSError, NotImplementedError) as exc:
            raise QRCodeError("Clipboard image access is not available.") from exc
        if isinstance(clipboard_value, Image.Image):
            result = zxingcpp.read_barcode(clipboard_value)
            if result is not None and result.text:
                return result.text
        elif isinstance(clipboard_value, list):
            for item in clipboard_value:
                path = Path(item)
                if path.is_file():
                    try:
                        return self.scan_image(path)
                    except QRCodeError:
                        continue
        raise QRCodeError("The clipboard does not contain a readable QR image.")

    def _mark_nonce(self, nonce: str, expires_at: str) -> bool:
        if self.repository is not None:
            return self.repository.mark_nonce_used(nonce, "qr", expires_at)
        if nonce in self._used_nonces:
            return False
        self._used_nonces.add(nonce)
        return True

    @staticmethod
    def _validate_safe_payload(payload_type: str, raw: bytes) -> None:
        if payload_type == "public_key":
            try:
                serialization.load_pem_public_key(raw)
            except (TypeError, ValueError) as exc:
                raise QRCodeError("Public-key QR payload is invalid.") from exc
        elif payload_type == "encrypted_entry":
            try:
                package = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise QRCodeError("Encrypted-entry QR payload is invalid.") from exc
            if (
                not isinstance(package, dict)
                or not isinstance(package.get("encryption"), dict)
                or "data" not in package
            ):
                raise QRCodeError("QR codes may contain only encrypted entry packages.")
        elif payload_type == "share_link" and not raw.startswith(
            b"cryptosafe://share/"
        ):
            raise QRCodeError("Share-link QR payload is invalid.")
