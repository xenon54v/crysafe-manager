from __future__ import annotations

import json

import pytest

from src.core.import_export.errors import ImportValidationError
from src.core.import_export.formats.csv_format import CSVFormatHandler
from src.core.import_export.formats.native_json import NativeJSONFormat
from src.core.import_export.formats.password_managers import PasswordManagerFormat


def test_csv_metadata_is_sanitized_and_semicolon_data_is_imported():
    encoded = CSVFormatHandler.encode(
        [{"title": "Mail", "tags": ["personal", "important"]}],
        metadata={"source\nname": "safe\rvalue"},
    )
    decoded = CSVFormatHandler.decode(
        b"name;login_username;login_password;login_uri;extra;grouping\n"
        b"Mail;user;secret;https://example.com;note;Personal\n"
    )

    assert b"source name: safe value" in encoded
    assert decoded == [
        {
            "title": "Mail",
            "username": "user",
            "password": "secret",
            "url": "https://example.com",
            "notes": "note",
            "category": "Personal",
            "tags": "",
        }
    ]


@pytest.mark.parametrize(
    "payload",
    [b"\xff\xfe", b"", b"username,password\nuser,secret\n"],
)
def test_csv_rejects_invalid_encoding_or_missing_title(payload):
    with pytest.raises(ImportValidationError):
        CSVFormatHandler.decode(payload)


def test_bitwarden_skips_non_login_items_and_preserves_custom_fields():
    payload = {
        "items": [
            {"type": 2, "name": "Secure note"},
            {
                "type": 1,
                "name": "Mail",
                "notes": "note",
                "login": {
                    "username": "student",
                    "password": "secret",
                    "uris": [{"uri": "https://example.com"}],
                },
                "fields": [
                    {"name": "category", "value": "Study"},
                    {"name": "tags", "value": "mail,course"},
                    "ignored",
                ],
            },
        ]
    }

    entries = PasswordManagerFormat.decode_bitwarden(json.dumps(payload).encode())
    reencoded = PasswordManagerFormat.encode_bitwarden(entries)

    assert len(entries) == 1
    assert entries[0]["category"] == "Study"
    assert entries[0]["tags"] == "mail,course"
    assert json.loads(reencoded)["items"][0]["name"] == "Mail"


@pytest.mark.parametrize("payload", [b"not-json", b"[]", b'{"folders": []}'])
def test_bitwarden_rejects_invalid_root(payload):
    with pytest.raises(ImportValidationError):
        PasswordManagerFormat.decode_bitwarden(payload)


def test_lastpass_and_native_json_round_trip_and_validation():
    entries = [
        {
            "title": "Portal",
            "username": "user",
            "password": "secret",
            "url": "https://example.com",
            "notes": "note",
            "category": "Work",
        }
    ]
    lastpass = PasswordManagerFormat.encode_lastpass(entries)
    assert PasswordManagerFormat.decode_lastpass(lastpass)[0]["title"] == "Portal"

    package = {"cryptosafe_export": True, "version": NativeJSONFormat.VERSION}
    encoded = NativeJSONFormat.encode(package)
    decoded = NativeJSONFormat.decode(encoded)
    assert NativeJSONFormat.is_native(decoded)
    assert NativeJSONFormat.associated_data(decoded)

    with pytest.raises(ImportValidationError):
        NativeJSONFormat.decode(b"[]")
    with pytest.raises(ImportValidationError):
        NativeJSONFormat.decode(b"\xff")
