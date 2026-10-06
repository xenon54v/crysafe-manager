from __future__ import annotations

import ctypes
import sys
from types import SimpleNamespace

import pytest

from src.core.security.platform_security import (
    FallbackActivityDetector,
    LinuxActivityDetector,
    LinuxKernelKeyring,
    MacOSActivityDetector,
    WindowsActivityDetector,
    create_activity_detector,
    detect_platform_capabilities,
)
from src.core.vault import url_tools


def test_activity_detector_factory_for_all_platforms():
    assert isinstance(create_activity_detector("Windows"), WindowsActivityDetector)
    assert isinstance(create_activity_detector("Darwin"), MacOSActivityDetector)
    assert isinstance(create_activity_detector("Linux"), LinuxActivityDetector)
    assert isinstance(create_activity_detector("Plan9"), FallbackActivityDetector)


def test_windows_detector_reads_idle_time_and_lock(monkeypatch):
    def get_last_input(pointer):
        pointer._obj.dwTime = 2_000
        return True

    user32 = SimpleNamespace(
        GetLastInputInfo=get_last_input,
        OpenInputDesktop=lambda *_args: 12,
        CloseDesktop=lambda _desktop: True,
    )
    kernel32 = SimpleNamespace(GetTickCount64=lambda: 5_500)
    monkeypatch.setattr(
        ctypes,
        "windll",
        SimpleNamespace(user32=user32, kernel32=kernel32),
        raising=False,
    )
    detector = WindowsActivityDetector()

    assert detector.idle_seconds() == 3.5
    assert not detector.screen_locked()

    user32.OpenInputDesktop = lambda *_args: 0
    assert detector.screen_locked()


def test_macos_detector_uses_quartz_and_degrades_safely(monkeypatch):
    quartz = SimpleNamespace(
        kCGEventSourceStateCombinedSessionState=1,
        kCGAnyInputEventType=2,
        CGEventSourceSecondsSinceLastEventType=lambda *_args: 7.25,
        CGSessionCopyCurrentDictionary=lambda: {"CGSSessionScreenIsLocked": True},
    )
    monkeypatch.setitem(sys.modules, "Quartz", quartz)
    detector = MacOSActivityDetector()

    assert detector.idle_seconds() == 7.25
    assert detector.screen_locked()

    quartz.CGEventSourceSecondsSinceLastEventType = lambda *_args: "invalid"
    quartz.CGSessionCopyCurrentDictionary = lambda: None
    assert detector.idle_seconds() is None
    assert not detector.screen_locked()


def test_linux_detector_commands_cache_and_failures(monkeypatch):
    monkeypatch.setenv("DISPLAY", ":1")
    monkeypatch.setenv("XDG_SESSION_ID", "session-2")
    monkeypatch.setattr(
        "src.core.security.platform_security.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    calls: list[list[str]] = []

    def fake_run(command, **_options):
        calls.append(command)
        output = "2500\n" if command[0].endswith("xprintidle") else "yes\n"
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr("src.core.security.platform_security.subprocess.run", fake_run)
    detector = LinuxActivityDetector()

    assert detector.idle_seconds() == 2.5
    assert detector.screen_locked()
    assert detector.screen_locked()
    assert len([call for call in calls if "show-session" in call]) == 1

    def fail_run(*_args, **_kwargs):
        raise OSError("missing")

    monkeypatch.setattr("src.core.security.platform_security.subprocess.run", fail_run)
    detector._last_lock_check = 0
    assert detector.idle_seconds() is None
    assert not detector.screen_locked()


def test_linux_kernel_keyring_rejects_errors_and_invalid_results(monkeypatch):
    monkeypatch.setattr(
        "src.core.security.platform_security.os.path.exists", lambda _path: True
    )
    keyring = LinuxKernelKeyring("/usr/bin/keyctl")

    monkeypatch.setattr(
        "src.core.security.platform_security.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=b"not-a-number"),
    )
    assert keyring.save_secret("session", b"secret") is None
    assert keyring.read_secret("invalid") is None
    assert not keyring.revoke("invalid")

    def fail(*_args, **_kwargs):
        raise OSError("unavailable")

    monkeypatch.setattr("src.core.security.platform_security.subprocess.run", fail)
    assert keyring.save_secret("session", b"secret") is None
    assert keyring.read_secret("123") is None
    assert not keyring.revoke("123")


def test_platform_capabilities_unknown_and_linux_policies(monkeypatch):
    monkeypatch.setattr(
        "src.core.security.platform_security.os.path.exists",
        lambda path: path in {"/proc/keys", "/sys/module/apparmor"},
    )
    monkeypatch.setattr(
        "src.core.security.platform_security.shutil.which",
        lambda name: "/usr/bin/systemctl" if name == "systemctl" else None,
    )

    linux = detect_platform_capabilities("Linux")
    unknown = detect_platform_capabilities("Plan9")

    assert linux.kernel_keyring
    assert linux.service_manager == "systemd"
    assert linux.mandatory_access_control == ("AppArmor",)
    assert not unknown.memory_lock
    assert unknown.service_manager is None


def test_url_normalization_validation_and_domain_extraction():
    assert (
        url_tools.normalize_url("Example.com/path#fragment")
        == "https://Example.com/path"
    )
    assert url_tools.normalize_url("  ") == ""
    assert url_tools.is_valid_url("https://example.com")
    assert url_tools.is_valid_url("")
    assert not url_tools.is_valid_url("ftp://example.com")
    assert url_tools.extract_domain("https://www.example.com/a") == "example.com"
    assert url_tools.extract_domain("not a url") == "not a url"
    assert url_tools.extract_domain("") == ""


class FakeResponse:
    def __init__(self, body: bytes, declared_size: str | None = None) -> None:
        self.body = body
        self.headers = {}
        if declared_size is not None:
            self.headers["Content-Length"] = declared_size

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, amount: int) -> bytes:
        return self.body[:amount]


def test_favicon_download_limits_and_private_address_block(monkeypatch):
    monkeypatch.setattr(
        url_tools.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 0))],
    )
    monkeypatch.setattr(
        url_tools,
        "urlopen",
        lambda *_args, **_kwargs: FakeResponse(b"ICON", "4"),
    )
    assert url_tools.fetch_favicon("example.com") == b"ICON"

    monkeypatch.setattr(
        url_tools,
        "urlopen",
        lambda *_args, **_kwargs: FakeResponse(b"too-large", "900000"),
    )
    assert url_tools.fetch_favicon("example.com", max_bytes=10) is None

    monkeypatch.setattr(
        url_tools.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("127.0.0.1", 0))],
    )
    assert url_tools.fetch_favicon("localhost") is None


def test_favicon_network_and_resolution_errors(monkeypatch):
    def resolution_failure(*_args, **_kwargs):
        raise OSError("dns")

    monkeypatch.setattr(url_tools.socket, "getaddrinfo", resolution_failure)
    assert url_tools.fetch_favicon("example.com") is None
    assert url_tools.fetch_favicon("ftp://example.com") is None


@pytest.mark.parametrize("address", ["10.0.0.1", "::1", "169.254.1.1"])
def test_non_public_addresses_are_rejected(monkeypatch, address):
    monkeypatch.setattr(
        url_tools.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, (address, 0))],
    )
    assert not url_tools._has_public_address("https://example.com")
