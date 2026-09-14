import string

import pytest

from src.core.vault.password_generator import PasswordGenerator


def test_default_password_meets_sprint_requirements():
    generator = PasswordGenerator()
    password = generator.generate()

    assert len(password) == 16
    assert any(character in string.ascii_uppercase for character in password)
    assert any(character in string.ascii_lowercase for character in password)
    assert any(character in string.digits for character in password)
    assert any(character in generator.SYMBOLS for character in password)
    assert not set(password).intersection(generator.AMBIGUOUS_CHARACTERS)
    assert generator.strength(password).score >= 3


def test_generator_supports_configurable_character_sets():
    generator = PasswordGenerator()
    password = generator.generate(
        length=24,
        use_uppercase=True,
        use_lowercase=False,
        use_digits=True,
        use_symbols=False,
        exclude_ambiguous=False,
    )

    assert len(password) == 24
    assert set(password).issubset(set(string.ascii_uppercase + string.digits))
    assert any(character.isupper() for character in password)
    assert any(character.isdigit() for character in password)


def test_recent_history_contains_only_last_twenty_passwords():
    generator = PasswordGenerator()
    generated = [generator.generate() for _ in range(25)]

    assert generator.recent_passwords() == tuple(generated[-20:])


def test_ten_thousand_generated_passwords_are_unique_and_valid():
    generator = PasswordGenerator()
    passwords = {generator.generate() for _ in range(10_000)}

    assert len(passwords) == 10_000
    assert all(generator.strength(password).score >= 3 for password in passwords)


@pytest.mark.parametrize("length", [7, 65])
def test_length_outside_required_range_is_rejected(length):
    with pytest.raises(ValueError):
        PasswordGenerator().generate(length=length)
