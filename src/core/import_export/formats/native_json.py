from __future__ import annotations

import json
from typing import Any

from ..crypto import canonical_json
from ..errors import ImportValidationError


class NativeJSONFormat:
    """Encode and validate the native JSON interchange format."""

    VERSION = "1.0"

    @classmethod
    def encode(cls, package: dict[str, Any]) -> bytes:
        return json.dumps(package, ensure_ascii=False, sort_keys=True, indent=2).encode(
            "utf-8"
        )

    @classmethod
    def decode(cls, data: bytes) -> dict[str, Any]:
        try:
            value = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ImportValidationError("The file is not valid UTF-8 JSON.") from exc
        if not isinstance(value, dict):
            raise ImportValidationError("The JSON root must be an object.")
        return value

    @classmethod
    def is_native(cls, value: dict[str, Any]) -> bool:
        return value.get("cryptosafe_export") is True

    @staticmethod
    def associated_data(package: dict[str, Any]) -> bytes:
        protected = {
            "version": package.get("version"),
            "cryptosafe_export": package.get("cryptosafe_export"),
            "timestamp": package.get("timestamp"),
            "source_application": package.get("source_application"),
            "content_format": package.get("content_format"),
            "compressed": package.get("compressed", False),
            "sender_public_key": package.get("sender_public_key"),
        }
        return canonical_json(protected)
