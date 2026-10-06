from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

import run as launcher
from src.core.config import ConfigManager, Environment
from src.core.os_keychain import OSKeychain


def test_source_installation_check_and_version(capsys):
    healthy, problems = launcher.check_installation()

    assert healthy
    assert problems == []
    assert launcher.main(["--check"]) == 0
    assert "installation check passed" in capsys.readouterr().out


def test_installation_check_reports_missing_dependency(monkeypatch, capsys):
    real_import = importlib.import_module

    def fake_import(name: str):
        if name == "argon2":
            raise ImportError("missing", name=name)
        return real_import(name)

    monkeypatch.setattr(launcher.importlib, "import_module", fake_import)

    assert launcher.main(["--check"]) == 1
    assert "argon2" in capsys.readouterr().err


def test_development_and_override_paths(monkeypatch, tmp_path):
    manager = ConfigManager(Environment.DEVELOPMENT)
    config = manager.load()

    assert config.db_path.name == "cryptosafe_dev.db"
    assert config.env is Environment.DEVELOPMENT

    explicit = tmp_path / "custom" / "vault.db"
    monkeypatch.setenv("CRYPTOSAFE_DB_PATH", str(explicit))
    monkeypatch.setenv("CRYPTOSAFE_THEME", "dark")
    monkeypatch.setenv("CRYPTOSAFE_LANG", "ru")
    overridden = manager.load()

    assert overridden.db_path == explicit
    assert overridden.user_prefs == {"language": "ru", "theme": "dark"}


@pytest.mark.parametrize(
    ("system", "variable", "relative"),
    [
        ("Windows", "LOCALAPPDATA", Path("CryptoSafe Manager")),
        ("Linux", "XDG_DATA_HOME", Path("cryptosafe-manager")),
    ],
)
def test_production_data_paths(monkeypatch, tmp_path, system, variable, relative):
    monkeypatch.setattr("src.core.config.platform.system", lambda: system)
    monkeypatch.setenv(variable, str(tmp_path))

    directory = ConfigManager(Environment.PRODUCTION).default_data_directory()

    assert directory == tmp_path / relative


def test_macos_production_data_path(monkeypatch, tmp_path):
    monkeypatch.setattr("src.core.config.platform.system", lambda: "Darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    directory = ConfigManager(Environment.PRODUCTION).default_data_directory()

    assert (
        directory == tmp_path / "Library" / "Application Support" / "CryptoSafe Manager"
    )


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.fail = False

    def set_password(self, service: str, name: str, value: str) -> None:
        if self.fail:
            raise RuntimeError("unavailable")
        self.values[(service, name)] = value

    def get_password(self, service: str, name: str) -> str | None:
        if self.fail:
            raise RuntimeError("unavailable")
        return self.values.get((service, name))

    def delete_password(self, service: str, name: str) -> None:
        if self.fail:
            raise RuntimeError("unavailable")
        self.values.pop((service, name), None)


def test_os_keychain_success_and_backend_failures(monkeypatch):
    fake = FakeKeyring()
    monkeypatch.setitem(sys.modules, "keyring", fake)
    keychain = OSKeychain()

    assert keychain.is_available()
    assert keychain.save_secret("vault", "secret")
    assert keychain.load_secret("vault") == "secret"
    assert keychain.delete_secret("vault")
    assert keychain.load_secret("vault") is None

    fake.fail = True
    assert not keychain.save_secret("vault", "secret")
    assert keychain.load_secret("vault") is None
    assert not keychain.delete_secret("vault")


def test_os_keychain_without_importable_backend(monkeypatch):
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "keyring":
            raise ImportError("disabled")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    keychain = OSKeychain()

    assert not keychain.is_available()
    assert not keychain.save_secret("vault", "secret")
    assert keychain.load_secret("vault") is None
    assert not keychain.delete_secret("vault")


def test_run_parser_rejects_unknown_argument():
    with pytest.raises(SystemExit) as exc_info:
        launcher.build_parser().parse_args(["--unknown"])

    assert exc_info.value.code == 2
