from __future__ import annotations

import csv
import io
from typing import Any

from ..errors import ImportValidationError


class CSVFormatHandler:
    """Encode and validate entries in the supported CSV format."""

    FIELDS = ("title", "username", "password", "url", "notes", "category", "tags")

    @classmethod
    def encode(
        cls,
        entries: list[dict[str, Any]],
        *,
        metadata: dict[str, str] | None = None,
    ) -> bytes:
        output = io.StringIO(newline="")
        if metadata:
            for key, value in metadata.items():
                safe_key = str(key).replace("\n", " ").replace("\r", " ")
                safe_value = str(value).replace("\n", " ").replace("\r", " ")
                output.write(f"# {safe_key}: {safe_value}\n")
        writer = csv.DictWriter(output, fieldnames=cls.FIELDS, extrasaction="ignore")
        writer.writeheader()
        for entry in entries:
            row = dict(entry)
            tags = row.get("tags", [])
            row["tags"] = ",".join(tags) if isinstance(tags, list) else str(tags)
            writer.writerow(row)
        return output.getvalue().encode("utf-8-sig")

    @classmethod
    def decode(cls, data: bytes) -> list[dict[str, Any]]:
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ImportValidationError("CSV must use UTF-8 encoding.") from exc
        lines = [
            line for line in text.splitlines(keepends=True) if not line.startswith("#")
        ]
        sample = "".join(lines[:20])
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO("".join(lines)), dialect=dialect)
        if not reader.fieldnames:
            raise ImportValidationError("CSV header is missing.")
        normalized = {
            str(name).strip().casefold() for name in reader.fieldnames if name
        }
        if not {"title", "name"} & normalized:
            raise ImportValidationError("CSV does not contain a title or name column.")
        entries = []
        for row in reader:
            lowered = {
                str(key).strip().casefold(): value for key, value in row.items() if key
            }
            entries.append(
                {
                    "title": lowered.get("title", lowered.get("name", "")),
                    "username": lowered.get(
                        "username", lowered.get("login_username", "")
                    ),
                    "password": lowered.get(
                        "password", lowered.get("login_password", "")
                    ),
                    "url": lowered.get("url", lowered.get("login_uri", "")),
                    "notes": lowered.get("notes", lowered.get("extra", "")),
                    "category": lowered.get("category", lowered.get("grouping", "")),
                    "tags": lowered.get("tags", ""),
                }
            )
        return entries
