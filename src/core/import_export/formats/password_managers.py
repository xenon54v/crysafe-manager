from __future__ import annotations

import json
from typing import Any

from ..errors import ImportValidationError
from .csv_format import CSVFormatHandler


class PasswordManagerFormat:
    """Provide password manager format operations."""

    @staticmethod
    def encode_bitwarden(entries: list[dict[str, Any]]) -> bytes:
        items = []
        for entry in entries:
            uri = str(entry.get("url", ""))
            items.append(
                {
                    "type": 1,
                    "name": str(entry.get("title", "")),
                    "notes": str(entry.get("notes", "")),
                    "favorite": False,
                    "login": {
                        "username": str(entry.get("username", "")),
                        "password": str(entry.get("password", "")),
                        "uris": [{"match": None, "uri": uri}] if uri else [],
                    },
                    "fields": [
                        {
                            "name": "category",
                            "value": str(entry.get("category", "")),
                            "type": 0,
                        },
                        {
                            "name": "tags",
                            "value": ",".join(entry.get("tags", [])),
                            "type": 0,
                        },
                    ],
                }
            )
        return json.dumps(
            {"encrypted": False, "folders": [], "items": items},
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")

    @staticmethod
    def decode_bitwarden(data: bytes) -> list[dict[str, Any]]:
        try:
            root = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ImportValidationError("Bitwarden JSON is invalid.") from exc
        if not isinstance(root, dict) or not isinstance(root.get("items"), list):
            raise ImportValidationError("Bitwarden items are missing.")
        entries = []
        for item in root["items"]:
            if not isinstance(item, dict) or item.get("type", 1) != 1:
                continue
            login = item.get("login") if isinstance(item.get("login"), dict) else {}
            uris = login.get("uris") if isinstance(login.get("uris"), list) else []
            url = ""
            if uris and isinstance(uris[0], dict):
                url = str(uris[0].get("uri", ""))
            custom = {
                str(field.get("name", "")).casefold(): str(field.get("value", ""))
                for field in item.get("fields", [])
                if isinstance(field, dict)
            }
            entries.append(
                {
                    "title": str(item.get("name", "")),
                    "username": str(login.get("username", "")),
                    "password": str(login.get("password", "")),
                    "url": url,
                    "notes": str(item.get("notes", "")),
                    "category": custom.get("category", ""),
                    "tags": custom.get("tags", ""),
                }
            )
        return entries

    @staticmethod
    def encode_lastpass(entries: list[dict[str, Any]]) -> bytes:
        remapped = []
        for entry in entries:
            remapped.append(
                {
                    "url": entry.get("url", ""),
                    "username": entry.get("username", ""),
                    "password": entry.get("password", ""),
                    "extra": entry.get("notes", ""),
                    "name": entry.get("title", ""),
                    "grouping": entry.get("category", ""),
                    "fav": "0",
                }
            )
        import csv
        import io

        output = io.StringIO(newline="")
        writer = csv.DictWriter(
            output,
            fieldnames=(
                "url",
                "username",
                "password",
                "extra",
                "name",
                "grouping",
                "fav",
            ),
        )
        writer.writeheader()
        writer.writerows(remapped)
        return output.getvalue().encode("utf-8-sig")

    @staticmethod
    def decode_lastpass(data: bytes) -> list[dict[str, Any]]:
        return CSVFormatHandler.decode(data)
