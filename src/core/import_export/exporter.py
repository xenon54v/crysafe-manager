from __future__ import annotations

import gzip
import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.security.memory_guard import MemoryGuard, ProtectedSecret
from src.database.exchange_repo import ExchangeRepository

from .crypto import (
    b64encode,
    clear_bytes,
    encrypt_payload_with_password,
    encrypt_payload_with_public_key,
)
from .errors import ExportError
from .formats import CSVFormatHandler, NativeJSONFormat, PasswordManagerFormat

SUPPORTED_EXPORT_FORMATS = {
    "encrypted_json",
    "csv",
    "bitwarden_json",
    "lastpass_csv",
}


@dataclass(frozen=True)
class ExportOptions:
    """Store export options values."""

    format_name: str = "encrypted_json"
    entry_ids: tuple[str, ...] | None = None
    excluded_fields: frozenset[str] = field(default_factory=frozenset)
    encryption_bits: int = 256
    compress: bool = False
    encrypt: bool = True
    allow_plaintext: bool = False

    def __post_init__(self) -> None:
        if self.format_name not in SUPPORTED_EXPORT_FORMATS:
            raise ValueError("Unsupported export format.")
        if self.encryption_bits not in {128, 256}:
            raise ValueError("Encryption strength must be 128 or 256 bits.")
        allowed = {
            "username",
            "password",
            "url",
            "notes",
            "category",
            "tags",
            "totp_secret",
            "sharing_metadata",
        }
        if not self.excluded_fields <= allowed:
            raise ValueError("An unsupported field was selected for exclusion.")
        if not self.encrypt and not self.allow_plaintext:
            raise ValueError("Plaintext export requires explicit migration approval.")
        if not self.encrypt and self.format_name == "encrypted_json":
            raise ValueError("Native encrypted JSON cannot be exported as plaintext.")


@dataclass(frozen=True)
class ExportArtifact:
    """Store export artifact values."""

    data: bytes
    format_name: str
    filename: str
    entry_count: int
    checksum: str
    encrypted: bool
    encryption_method: str


class VaultExporter:
    """Exports decrypted entries only within a short-lived protected operation."""

    def __init__(
        self,
        entry_manager,
        key_manager,
        *,
        db=None,
        audit_logger=None,
        confirm_master_password: Callable[[str], bool] | None = None,
        interrupt_check: Callable[[], None] | None = None,
        memory_guard: MemoryGuard | None = None,
    ) -> None:
        self.entry_manager = entry_manager
        self.key_manager = key_manager
        self.db = db or entry_manager.db
        self.audit_logger = audit_logger
        self.confirm_master_password = confirm_master_password
        self.interrupt_check = interrupt_check
        self.memory_guard = memory_guard
        self.repository = ExchangeRepository(self.db)

    def export(
        self,
        options: ExportOptions | None = None,
        *,
        master_password: str,
        export_password: str | None = None,
        recipient_public_key: bytes | None = None,
        sender_public_key: bytes | None = None,
    ) -> ExportArtifact:
        options = options or ExportOptions()
        self._check_interrupted()
        if not self._confirm(master_password):
            self._audit("VAULT_EXPORT_REJECTED", "WARN", {"reason": "authentication"})
            raise ExportError("Master password confirmation failed.")
        if options.encrypt and not export_password and recipient_public_key is None:
            self._audit(
                "VAULT_EXPORT_REJECTED",
                "WARN",
                {"reason": "missing_export_key", "format": options.format_name},
            )
            raise ExportError("Choose an export password or recipient public key.")

        payload_buffer: bytearray | None = None
        protected_payload: ProtectedSecret | None = None
        entries: list[dict[str, Any]] = []
        filtered: list[dict[str, Any]] = []
        try:
            entries = self._select_entries(options.entry_ids)
            self._check_interrupted()
            filtered = [
                self._filter_entry(entry, options.excluded_fields) for entry in entries
            ]
            payload, content_format, extension = self._encode_payload(
                filtered, options.format_name
            )
            self._check_interrupted()
            payload_buffer = bytearray(payload)
            del payload
            if self.memory_guard is not None:
                protected_payload = self.memory_guard.protect(payload_buffer)
                clear_bytes(payload_buffer)
                payload_buffer = None
            if options.compress:
                source_buffer = (
                    protected_payload.read()
                    if protected_payload is not None
                    else payload_buffer
                )
                compressed = gzip.compress(
                    bytes(source_buffer), compresslevel=6, mtime=0
                )
                clear_bytes(source_buffer)
                clear_bytes(payload_buffer)
                payload_buffer = bytearray(compressed)
                del compressed
                if protected_payload is not None:
                    protected_payload.close()
                    protected_payload = self.memory_guard.protect(payload_buffer)
                    clear_bytes(payload_buffer)
                    payload_buffer = None

            timestamp = datetime.now(timezone.utc).isoformat()
            if options.encrypt:
                header: dict[str, Any] = {
                    "version": NativeJSONFormat.VERSION,
                    "cryptosafe_export": True,
                    "timestamp": timestamp,
                    "source_application": "CryptoSafe Manager",
                    "content_format": content_format,
                    "compressed": options.compress,
                }
                if sender_public_key is not None:
                    header["sender_public_key"] = b64encode(sender_public_key)
                associated_data = NativeJSONFormat.associated_data(header)
                source_buffer = (
                    protected_payload.read()
                    if protected_payload is not None
                    else payload_buffer
                )
                try:
                    if recipient_public_key is not None:
                        encrypted = encrypt_payload_with_public_key(
                            bytes(source_buffer),
                            recipient_public_key,
                            associated_data=associated_data,
                            sender_public_key=None,
                        )
                    else:
                        encrypted = encrypt_payload_with_password(
                            bytes(source_buffer),
                            export_password or "",
                            key_size=options.encryption_bits // 8,
                            associated_data=associated_data,
                        )
                finally:
                    clear_bytes(source_buffer)
                self._check_interrupted()
                package = {**header, **encrypted}
                output = NativeJSONFormat.encode(package)
                encryption_method = str(package["encryption"]["algorithm"])
                extension = ".csm.json"
            else:
                source_buffer = (
                    protected_payload.read()
                    if protected_payload is not None
                    else payload_buffer
                )
                output = bytes(source_buffer)
                clear_bytes(source_buffer)
                encryption_method = "PLAINTEXT_MIGRATION"
            clear_bytes(payload_buffer)
            payload_buffer = None
            checksum = hashlib.sha256(output).hexdigest()
            artifact = ExportArtifact(
                data=output,
                format_name=options.format_name,
                filename=self._filename(options.format_name, extension),
                entry_count=len(filtered),
                checksum=checksum,
                encrypted=options.encrypt,
                encryption_method=encryption_method,
            )
            self.repository.add_history(
                operation_type="export",
                format_name=options.format_name,
                encryption_method=encryption_method,
                entry_count=len(filtered),
                file_size=len(output),
                checksum=checksum,
                verification_status="verified",
                details={
                    "selective": options.entry_ids is not None,
                    "compressed": options.compress,
                    "excluded_fields": sorted(options.excluded_fields),
                },
            )
            self._audit(
                "VAULT_EXPORT_COMPLETED",
                "INFO" if options.encrypt else "WARN",
                {
                    "format": options.format_name,
                    "entry_count": len(filtered),
                    "encrypted": options.encrypt,
                    "compressed": options.compress,
                    "checksum": checksum,
                },
            )
            return artifact
        except ExportError:
            raise
        except Exception as exc:
            self._audit(
                "VAULT_EXPORT_FAILED",
                "ERROR",
                {"format": options.format_name, "error_type": type(exc).__name__},
            )
            raise ExportError("Vault export could not be completed.") from exc
        finally:
            clear_bytes(payload_buffer)
            if protected_payload is not None:
                protected_payload.close()
            for collection in (filtered, entries):
                for entry in collection:
                    entry.clear()
                collection.clear()

    def export_to_file(
        self,
        destination: Path | str,
        options: ExportOptions | None = None,
        **credentials,
    ) -> ExportArtifact:
        artifact = self.export(options, **credentials)
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            descriptor, temp_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            temporary_path = Path(temp_name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(artifact.data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, path)
            temporary_path = None
        finally:
            if temporary_path is not None and temporary_path.exists():
                try:
                    self._wipe_file(temporary_path)
                    temporary_path.unlink()
                except OSError:
                    temporary_path.unlink(missing_ok=True)
        return artifact

    def preview(self, options: ExportOptions | None = None) -> dict[str, Any]:
        options = options or ExportOptions()
        entries = self._select_entries(options.entry_ids)
        try:
            return {
                "format": options.format_name,
                "entry_count": len(entries),
                "titles": [str(entry.get("title", "")) for entry in entries],
                "excluded_fields": sorted(options.excluded_fields),
                "encrypted": options.encrypt,
                "compressed": options.compress,
            }
        finally:
            for entry in entries:
                entry.clear()
            entries.clear()

    def _select_entries(
        self, entry_ids: tuple[str, ...] | None
    ) -> list[dict[str, Any]]:
        if entry_ids is None:
            return self.entry_manager.get_all_entries()
        selected = []
        seen = set()
        for entry_id in entry_ids:
            if entry_id in seen:
                continue
            seen.add(entry_id)
            entry = self.entry_manager.get_entry(entry_id)
            if entry is None:
                raise ExportError("A selected vault entry no longer exists.")
            selected.append(entry)
        return selected

    @staticmethod
    def _filter_entry(
        entry: dict[str, Any], excluded_fields: frozenset[str]
    ) -> dict[str, Any]:
        allowed = {
            "title",
            "username",
            "password",
            "url",
            "notes",
            "category",
            "tags",
            "totp_secret",
            "sharing_metadata",
            "created_at",
            "updated_at",
            "version",
        }
        return {
            key: value
            for key, value in entry.items()
            if key in allowed and key not in excluded_fields
        }

    @staticmethod
    def _encode_payload(
        entries: list[dict[str, Any]], format_name: str
    ) -> tuple[bytes, str, str]:
        metadata = {"source": "CryptoSafe Manager", "version": "1.0"}
        if format_name == "encrypted_json":
            payload = json.dumps(
                {"version": "1.0", "entries": entries},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            return payload, "cryptosafe_json", ".csm.json"
        if format_name == "csv":
            return CSVFormatHandler.encode(entries, metadata=metadata), "csv", ".csv"
        if format_name == "bitwarden_json":
            return (
                PasswordManagerFormat.encode_bitwarden(entries),
                "bitwarden_json",
                ".json",
            )
        if format_name == "lastpass_csv":
            return (
                PasswordManagerFormat.encode_lastpass(entries),
                "lastpass_csv",
                ".csv",
            )
        raise ExportError("Unsupported export format.")

    def _confirm(self, master_password: str) -> bool:
        if not master_password:
            return False
        if self.confirm_master_password is not None:
            return bool(self.confirm_master_password(master_password))
        row = self.db.execute(
            "SELECT hash FROM key_store WHERE key_type = ? LIMIT 1;", ("master",)
        ).fetchone()
        if row is None:
            return False
        stored_hash = row[0].decode("utf-8") if isinstance(row[0], bytes) else row[0]
        return self.key_manager.verify_password(master_password, stored_hash)

    def _audit(self, event: str, severity: str, details: dict[str, Any]) -> None:
        if self.audit_logger is not None:
            self.audit_logger.log_event(
                event,
                severity=severity,
                source="vault_exporter",
                details=details,
                user_id="local_user",
            )

    def _check_interrupted(self) -> None:
        if self.interrupt_check is not None:
            self.interrupt_check()

    @staticmethod
    def _wipe_file(path: Path) -> None:
        size = path.stat().st_size
        block = b"\x00" * min(1_048_576, max(1, size))
        with path.open("r+b", buffering=0) as stream:
            remaining = size
            while remaining > 0:
                chunk_size = min(remaining, len(block))
                stream.write(block[:chunk_size])
                remaining -= chunk_size
            stream.flush()
            os.fsync(stream.fileno())

    @staticmethod
    def _filename(format_name: str, extension: str) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"cryptosafe-{format_name}-{stamp}{extension}"
