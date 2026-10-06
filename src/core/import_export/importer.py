from __future__ import annotations

import hashlib
import multiprocessing
import queue
import re
import time
import uuid
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.security.memory_guard import MemoryGuard
from src.database.exchange_repo import ExchangeRepository

from .crypto import (
    clear_bytes,
    decrypt_payload_with_password,
    decrypt_payload_with_private_key,
)
from .errors import ImportValidationError
from .formats import CSVFormatHandler, NativeJSONFormat, PasswordManagerFormat

SUPPORTED_IMPORT_FORMATS = {
    "encrypted_json",
    "csv",
    "bitwarden_json",
    "lastpass_csv",
}
_MALICIOUS_TEXT = re.compile(
    r"(?is)<\s*script\b|javascript\s*:|vbscript\s*:|<\?php|\bpowershell(?:\.exe)?\b|\bcmd\.exe\b"
)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class ImportOptions:
    """Store import options values."""

    mode: str = "merge"
    conflict_action: str = "update"
    format_name: str | None = None
    max_file_size: int = 10 * 1024 * 1024
    timeout_seconds: float = 30.0
    allow_partial: bool = False
    checkpoint_id: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in {"merge", "replace", "dry_run"}:
            raise ValueError("Import mode must be merge, replace, or dry_run.")
        if self.conflict_action not in {"update", "skip", "duplicate"}:
            raise ValueError("Unsupported conflict action.")
        if (
            self.format_name is not None
            and self.format_name not in SUPPORTED_IMPORT_FORMATS
        ):
            raise ValueError("Unsupported import format.")
        if not 1 <= self.max_file_size <= 100 * 1024 * 1024:
            raise ValueError("Import size limit must be between 1 byte and 100 MB.")
        if not 0.1 <= self.timeout_seconds <= 30.0:
            raise ValueError("Import timeout must not exceed 30 seconds.")
        if self.mode == "replace" and self.allow_partial:
            raise ValueError("Replace mode cannot use partial commits.")


@dataclass(frozen=True)
class ImportPreview:
    """Represent import preview behavior."""

    format_name: str
    entries: tuple[dict[str, Any], ...]
    new_count: int
    update_count: int
    skip_count: int
    warnings: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    encrypted: bool = False
    checksum: str = ""

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    def summary(self) -> dict[str, int]:
        return {
            "entries": self.entry_count,
            "new": self.new_count,
            "updated": self.update_count,
            "skipped": self.skip_count,
            "warnings": len(self.warnings),
            "errors": len(self.errors),
        }


@dataclass(frozen=True)
class ImportResult:
    """Store import result values."""

    format_name: str
    created: int
    updated: int
    skipped: int
    dry_run: bool
    checkpoint_id: str | None
    warnings: tuple[str, ...]


class VaultImporter:
    """Validates untrusted data before it reaches the encrypted vault."""

    def __init__(
        self,
        entry_manager,
        *,
        db=None,
        audit_logger=None,
        interrupt_check: Callable[[], None] | None = None,
        memory_guard: MemoryGuard | None = None,
    ) -> None:
        self.entry_manager = entry_manager
        self.db = db or entry_manager.db
        self.audit_logger = audit_logger
        self.interrupt_check = interrupt_check
        self.memory_guard = memory_guard
        self.repository = ExchangeRepository(self.db)

    def preview(
        self,
        source: bytes | bytearray | Path | str,
        options: ImportOptions | None = None,
        *,
        password: str | None = None,
        private_key: bytes | None = None,
        private_key_password: bytes | None = None,
    ) -> ImportPreview:
        options = options or ImportOptions(mode="dry_run")
        self._check_interrupted()
        started = time.monotonic()
        data = self._read_source(source, options.max_file_size)
        self._check_interrupted()
        checksum = hashlib.sha256(data).hexdigest()
        self._scan_file_signature(data)
        format_name = options.format_name or self.detect_format(data)
        content, content_format, encrypted = self._decode_envelope(
            data,
            format_name,
            password=password,
            private_key=private_key,
            private_key_password=private_key_password,
            max_output_size=options.max_file_size,
        )
        remaining = self._remaining(started, options.timeout_seconds)
        content_buffer = bytearray(content)
        del content
        protected_content = None
        try:
            if self.memory_guard is not None:
                protected_content = self.memory_guard.protect(content_buffer)
                clear_bytes(content_buffer)
                content_buffer = protected_content.read()
            parsed = self._parse_sandboxed(
                bytes(content_buffer), content_format, remaining
            )
        finally:
            clear_bytes(content_buffer)
            if protected_content is not None:
                protected_content.close()
        sanitized, warnings, errors = self._sanitize_entries(parsed)
        self._check_interrupted()
        existing = self.entry_manager.get_all_entries()
        new_count, update_count, skip_count = self._plan_counts(
            sanitized, existing, options.conflict_action
        )
        self._check_deadline(started, options.timeout_seconds)
        return ImportPreview(
            format_name=content_format,
            entries=tuple(sanitized),
            new_count=new_count,
            update_count=update_count,
            skip_count=skip_count,
            warnings=tuple(warnings),
            errors=tuple(errors),
            encrypted=encrypted,
            checksum=checksum,
        )

    def import_data(
        self,
        source: bytes | bytearray | Path | str,
        options: ImportOptions | None = None,
        **credentials,
    ) -> ImportResult:
        options = options or ImportOptions()
        self._check_interrupted()
        operation_started = time.monotonic()
        source_bytes = self._read_source(source, options.max_file_size)
        preview = self.preview(source_bytes, options, **credentials)
        if preview.errors:
            self._audit(
                "VAULT_IMPORT_REJECTED",
                "WARN",
                {"error_count": len(preview.errors), "format": preview.format_name},
            )
            raise ImportValidationError("; ".join(preview.errors))
        if options.mode == "dry_run":
            self._audit(
                "VAULT_IMPORT_DRY_RUN",
                "INFO",
                {"format": preview.format_name, **preview.summary()},
            )
            return ImportResult(
                preview.format_name,
                preview.new_count,
                preview.update_count,
                preview.skip_count,
                True,
                None,
                preview.warnings,
            )

        checkpoint_id = options.checkpoint_id or str(uuid.uuid4())
        start_index = self._checkpoint_index(checkpoint_id, preview.checksum)
        remaining_timeout = self._remaining(operation_started, options.timeout_seconds)
        started = time.monotonic()
        created = updated = skipped = 0
        current_entries = self.entry_manager.get_all_entries()
        existing_map = {self._identity(entry): entry for entry in current_entries}
        try:
            if options.allow_partial:
                for index, entry in enumerate(
                    preview.entries[start_index:], start=start_index
                ):
                    self._check_interrupted()
                    self._check_deadline(started, remaining_timeout)
                    action = self._apply_one(
                        entry, options.conflict_action, existing_map
                    )
                    created += action == "created"
                    updated += action == "updated"
                    skipped += action == "skipped"
                    self.repository.save_checkpoint(
                        checkpoint_id,
                        preview.checksum,
                        preview.format_name,
                        index + 1,
                        created + updated,
                    )
            else:
                with self.db.transaction(write=True):
                    if options.mode == "replace":
                        for current in current_entries:
                            self.entry_manager.delete_entry(
                                str(current["id"]), soft_delete=False
                            )
                        existing_map.clear()
                    for entry in preview.entries:
                        self._check_interrupted()
                        self._check_deadline(started, remaining_timeout)
                        action = self._apply_one(
                            entry, options.conflict_action, existing_map
                        )
                        created += action == "created"
                        updated += action == "updated"
                        skipped += action == "skipped"
            self.repository.clear_checkpoint(checkpoint_id)
        except Exception as exc:
            if options.allow_partial:
                self.repository.save_checkpoint(
                    checkpoint_id,
                    preview.checksum,
                    preview.format_name,
                    start_index + created + updated + skipped,
                    created + updated,
                )
            self._audit(
                "VAULT_IMPORT_FAILED",
                "ERROR",
                {
                    "format": preview.format_name,
                    "error_type": type(exc).__name__,
                    "checkpoint_id": checkpoint_id if options.allow_partial else None,
                },
            )
            if isinstance(exc, ImportValidationError):
                raise
            raise ImportValidationError("Vault import could not be completed.") from exc

        self.repository.add_history(
            operation_type="import",
            format_name=preview.format_name,
            encryption_method="encrypted"
            if preview.encrypted
            else "plaintext_migration",
            entry_count=created + updated,
            file_size=len(source_bytes),
            checksum=preview.checksum,
            verification_status="verified",
            details={
                "mode": options.mode,
                "created": created,
                "updated": updated,
                "skipped": skipped,
            },
        )
        self._audit(
            "VAULT_IMPORT_COMPLETED",
            "INFO",
            {
                "format": preview.format_name,
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "checksum": preview.checksum,
            },
        )
        return ImportResult(
            preview.format_name,
            created,
            updated,
            skipped,
            False,
            None,
            preview.warnings,
        )

    @staticmethod
    def detect_format(data: bytes) -> str:
        stripped = data.lstrip(b"\xef\xbb\xbf\x20\t\r\n")
        if stripped.startswith(b"{"):
            if re.search(rb'"cryptosafe_export"\s*:\s*true', stripped, re.IGNORECASE):
                return "encrypted_json"
            if re.search(rb'"items"\s*:', stripped, re.IGNORECASE):
                return "bitwarden_json"
            raise ImportValidationError(
                "JSON format could not be detected; select a format manually."
            )
        header = stripped[:4096].decode("utf-8-sig", errors="replace").casefold()
        first_data_line = next(
            (line for line in header.splitlines() if line and not line.startswith("#")),
            "",
        )
        if all(name in first_data_line for name in ("url", "username", "password")):
            if "extra" in first_data_line and "grouping" in first_data_line:
                return "lastpass_csv"
            return "csv"
        raise ImportValidationError(
            "File format could not be detected; select a format manually."
        )

    def _decode_envelope(
        self,
        data: bytes,
        format_name: str,
        *,
        password: str | None,
        private_key: bytes | None,
        private_key_password: bytes | None,
        max_output_size: int,
    ) -> tuple[bytes, str, bool]:
        if format_name != "encrypted_json":
            return data, format_name, False
        package = NativeJSONFormat.decode(data)
        if not NativeJSONFormat.is_native(package):
            raise ImportValidationError("Native export marker is missing.")
        associated_data = NativeJSONFormat.associated_data(package)
        algorithm = str(package.get("encryption", {}).get("algorithm", ""))
        if algorithm.startswith("AES-"):
            if password is None:
                raise ImportValidationError("An export password is required.")
            plaintext = decrypt_payload_with_password(
                package, password, associated_data=associated_data
            )
        else:
            if private_key is None:
                raise ImportValidationError("A recipient private key is required.")
            plaintext = decrypt_payload_with_private_key(
                package,
                private_key,
                private_key_password=private_key_password,
                associated_data=associated_data,
            )
        if package.get("compressed") is True:
            try:
                plaintext = self._decompress_limited(
                    plaintext, max_output_size=max_output_size
                )
            except (OSError, EOFError, zlib.error) as exc:
                raise ImportValidationError(
                    "Compressed export data is corrupted."
                ) from exc
        elif len(plaintext) > max_output_size:
            raise ImportValidationError(
                "Decrypted import data exceeds the configured size limit."
            )
        content_format = str(package.get("content_format", "cryptosafe_json"))
        if content_format not in {
            "cryptosafe_json",
            "csv",
            "bitwarden_json",
            "lastpass_csv",
        }:
            raise ImportValidationError("Encrypted content format is unsupported.")
        return plaintext, content_format, True

    @staticmethod
    def _decompress_limited(data: bytes, *, max_output_size: int) -> bytes:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        output = decompressor.decompress(data, max_output_size + 1)
        if len(output) > max_output_size or decompressor.unconsumed_tail:
            raise ImportValidationError(
                "Compressed import expands beyond the configured size limit."
            )
        output += decompressor.flush(max_output_size + 1 - len(output))
        if len(output) > max_output_size or not decompressor.eof:
            raise ImportValidationError(
                "Compressed import expands beyond the configured size limit."
            )
        return output

    @staticmethod
    def _read_source(source: bytes | bytearray | Path | str, limit: int) -> bytes:
        if isinstance(source, (bytes, bytearray)):
            data = bytes(source)
            if len(data) > limit:
                raise ImportValidationError(
                    "Import file exceeds the configured size limit."
                )
            return data
        path = Path(source)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ImportValidationError("Import file could not be read.") from exc
        if size > limit:
            raise ImportValidationError(
                "Import file exceeds the configured size limit."
            )
        try:
            return path.read_bytes()
        except OSError as exc:
            raise ImportValidationError("Import file could not be read.") from exc

    @staticmethod
    def _scan_file_signature(data: bytes) -> None:
        if data.startswith((b"MZ", b"\x7fELF", b"#!")):
            raise ImportValidationError(
                "Executable content is not accepted for import."
            )

    def _parse_sandboxed(
        self, data: bytes, format_name: str, timeout: float
    ) -> list[dict[str, Any]]:
        context = multiprocessing.get_context("spawn")
        result_queue = context.Queue(maxsize=1)
        process = context.Process(
            target=_parse_worker,
            args=(data, format_name, result_queue),
            daemon=True,
        )
        process.start()
        try:
            status, payload = result_queue.get(timeout=max(0.05, timeout))
        except queue.Empty as exc:
            process.terminate()
            process.join(timeout=1.0)
            raise ImportValidationError(
                "Import parsing exceeded the 30-second limit."
            ) from exc
        finally:
            result_queue.close()
        process.join(timeout=1.0)
        if process.is_alive():
            process.terminate()
            process.join(timeout=1.0)
        if status != "ok":
            raise ImportValidationError(str(payload))
        if not isinstance(payload, list):
            raise ImportValidationError("Imported entry collection is invalid.")
        return payload

    @staticmethod
    def _sanitize_entries(
        entries: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        sanitized: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []
        if len(entries) > 100_000:
            return [], [], ["Import contains too many entries."]
        for number, entry in enumerate(entries, start=1):
            if not isinstance(entry, dict):
                errors.append(f"Entry {number} is not an object.")
                continue
            cleaned: dict[str, Any] = {}
            for field_name in (
                "title",
                "username",
                "password",
                "url",
                "notes",
                "category",
                "totp_secret",
            ):
                value = entry.get(field_name, "")
                if not isinstance(value, (str, int, float)):
                    errors.append(f"Entry {number} has an invalid {field_name} value.")
                    value = ""
                text = str(value)
                if len(text) > (16_384 if field_name == "notes" else 4_096):
                    errors.append(
                        f"Entry {number} has an oversized {field_name} value."
                    )
                if _CONTROL_CHARACTERS.search(text):
                    text = _CONTROL_CHARACTERS.sub("", text)
                    warnings.append(
                        f"Entry {number}: invalid control characters were removed."
                    )
                if field_name != "password" and _MALICIOUS_TEXT.search(text):
                    text = (
                        ""
                        if field_name == "url"
                        else _MALICIOUS_TEXT.sub("[removed]", text)
                    )
                    warnings.append(
                        f"Entry {number}: potentially executable content was removed."
                    )
                cleaned[field_name] = text
            tags = entry.get("tags", [])
            if isinstance(tags, str):
                tags = [item.strip() for item in tags.split(",") if item.strip()]
            if not isinstance(tags, list):
                errors.append(f"Entry {number} has invalid tags.")
                tags = []
            cleaned["tags"] = [
                _CONTROL_CHARACTERS.sub("", str(item)).strip()[:128]
                for item in tags[:100]
                if str(item).strip()
            ]
            cleaned["sharing_metadata"] = {}
            cleaned["version"] = 1
            cleaned["title"] = cleaned["title"].strip()
            cleaned["username"] = cleaned["username"].strip()
            cleaned["url"] = cleaned["url"].strip()
            if not cleaned["title"]:
                errors.append(f"Entry {number} has no title.")
            if not cleaned["password"].strip():
                errors.append(f"Entry {number} has no password.")
            if cleaned["url"].casefold().startswith(("javascript:", "data:", "file:")):
                errors.append(f"Entry {number} contains an unsafe URL scheme.")
            sanitized.append(cleaned)
        return sanitized, warnings, errors

    @staticmethod
    def _identity(entry: dict[str, Any]) -> tuple[str, str, str]:
        return (
            str(entry.get("title", "")).strip().casefold(),
            str(entry.get("username", "")).strip().casefold(),
            str(entry.get("url", "")).strip().casefold(),
        )

    def _plan_counts(
        self,
        imported: list[dict[str, Any]],
        existing: list[dict[str, Any]],
        conflict_action: str,
    ) -> tuple[int, int, int]:
        identities = {self._identity(entry) for entry in existing}
        new = updated = skipped = 0
        for entry in imported:
            identity = self._identity(entry)
            if identity not in identities or conflict_action == "duplicate":
                new += 1
                identities.add(identity)
            elif conflict_action == "update":
                updated += 1
            else:
                skipped += 1
        return new, updated, skipped

    def _apply_one(
        self,
        entry: dict[str, Any],
        conflict_action: str,
        existing_map: dict[tuple[str, str, str], dict[str, Any]],
    ) -> str:
        identity = self._identity(entry)
        existing = existing_map.get(identity)
        if existing is None or conflict_action == "duplicate":
            created = self.entry_manager.create_entry(entry)
            if conflict_action != "duplicate":
                existing_map[identity] = created
            return "created"
        if conflict_action == "skip":
            return "skipped"
        updated = self.entry_manager.update_entry(str(existing["id"]), entry)
        existing_map[identity] = updated
        return "updated"

    def _checkpoint_index(self, checkpoint_id: str, checksum: str) -> int:
        row = self.repository.load_checkpoint(checkpoint_id)
        if row is None:
            return 0
        if str(row["source_checksum"]) != checksum:
            raise ImportValidationError("Import checkpoint does not match this file.")
        return max(0, int(row["next_index"]))

    @staticmethod
    def _remaining(started: float, timeout: float) -> float:
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise ImportValidationError("Import processing timed out.")
        return remaining

    @staticmethod
    def _check_deadline(started: float, timeout: float) -> None:
        if time.monotonic() - started > timeout:
            raise ImportValidationError("Import processing timed out.")

    def _audit(self, event: str, severity: str, details: dict[str, Any]) -> None:
        if self.audit_logger is not None:
            self.audit_logger.log_event(
                event,
                severity=severity,
                source="vault_importer",
                details=details,
                user_id="local_user",
            )

    def _check_interrupted(self) -> None:
        if self.interrupt_check is not None:
            self.interrupt_check()


def _parse_worker(data: bytes, format_name: str, result_queue) -> None:
    """Runs parsers in a process without access to the live database or vault keys."""

    try:
        if format_name == "cryptosafe_json":
            root = NativeJSONFormat.decode(data)
            entries = root.get("entries")
            if not isinstance(entries, list):
                raise ImportValidationError("Native export entries are missing.")
        elif format_name == "csv":
            entries = CSVFormatHandler.decode(data)
        elif format_name == "bitwarden_json":
            entries = PasswordManagerFormat.decode_bitwarden(data)
        elif format_name == "lastpass_csv":
            entries = PasswordManagerFormat.decode_lastpass(data)
        else:
            raise ImportValidationError("Unsupported content format.")
        result_queue.put(("ok", entries))
    except (ImportValidationError, KeyError, TypeError, ValueError) as exc:
        result_queue.put(("error", str(exc)))
