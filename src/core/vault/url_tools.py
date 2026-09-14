from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"

    parsed = urlsplit(value)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must contain a valid HTTP or HTTPS address.")
    return urlunsplit(
        (parsed.scheme.casefold(), parsed.netloc, parsed.path, parsed.query, "")
    )


def is_valid_url(value: str) -> bool:
    if not value.strip():
        return True
    try:
        normalize_url(value)
    except ValueError:
        return False
    return True


def extract_domain(value: str) -> str:
    if not value.strip():
        return ""
    try:
        hostname = urlsplit(normalize_url(value)).hostname or ""
    except ValueError:
        return ""
    return hostname[4:] if hostname.casefold().startswith("www.") else hostname


def fetch_favicon(
    value: str, timeout: float = 3.0, max_bytes: int = 512_000
) -> bytes | None:
    """Downloads a small favicon only from a publicly routable HTTP(S) host."""

    try:
        normalized = normalize_url(value)
        if not normalized or not _has_public_address(normalized):
            return None

        parsed = urlsplit(normalized)
        favicon_url = urlunsplit((parsed.scheme, parsed.netloc, "/favicon.ico", "", ""))
        request = Request(favicon_url, headers={"User-Agent": "CryptoSafe-Manager/3"})
        with urlopen(request, timeout=timeout) as response:
            declared_size = response.headers.get("Content-Length")
            if declared_size and int(declared_size) > max_bytes:
                return None
            data = response.read(max_bytes + 1)
            return data if 0 < len(data) <= max_bytes else None
    except (OSError, ValueError):
        return None


def _has_public_address(value: str) -> bool:
    hostname = urlsplit(value).hostname
    if not hostname:
        return False

    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError:
        return False

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            return False
    return bool(addresses)
