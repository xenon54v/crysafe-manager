from __future__ import annotations

import secrets
import string

class PasswordGenerator:

    DEFAULT_LENGTH = 20
    MIN_LENGTH = 12
    MAX_LENGTH = 64

    SIMILAR_CHARS = set("lI10O")

    SPECIAL_CHARS = "!@#$%^&*"

    def generate(
        self,
        length: int = DEFAULT_LENGTH,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_similar: bool = True,
    ) -> str:
        self._validate_length(length)

        groups: list[str] = []

        if use_uppercase:
            groups.append(string.ascii_uppercase)

        if use_lowercase:
            groups.append(string.ascii_lowercase)

        if use_digits:
            groups.append(string.digits)

        if use_special:
            groups.append(self.SPECIAL_CHARS)

        if not groups:
            raise ValueError("At least one character group must be selected.")

        if exclude_similar:
            groups = [
                self._remove_similar_chars(group)
                for group in groups
            ]

        required_chars = [
            secrets.choice(group)
            for group in groups
        ]

        if len(required_chars) > length:
            raise ValueError(
                "Password length is too short for selected character groups."
            )

        all_chars = "".join(groups)

        remaining_chars = [
            secrets.choice(all_chars)
            for _ in range(length - len(required_chars))
        ]

        password_chars = required_chars + remaining_chars
        secrets.SystemRandom().shuffle(password_chars)

        return "".join(password_chars)

    def _validate_length(self, length: int) -> None:
        if not isinstance(length, int):
            raise TypeError("Password length must be integer.")

        if length < self.MIN_LENGTH or length > self.MAX_LENGTH:
            raise ValueError(
                f"Password length must be from {self.MIN_LENGTH} to {self.MAX_LENGTH}."
            )

    def estimate_entropy(self, password: str) -> float:
        charset_size = 0

        if any(char in string.ascii_lowercase for char in password):
            charset_size += 26

        if any(char in string.ascii_uppercase for char in password):
            charset_size += 26

        if any(char in string.digits for char in password):
            charset_size += 10

        if any(char in self.SPECIAL_CHARS for char in password):
            charset_size += len(self.SPECIAL_CHARS)

        if charset_size == 0:
            return 0.0

        import math
        return len(password) * math.log2(charset_size)

    def _remove_similar_chars(self, chars: str) -> str:
        filtered = "".join(
            char for char in chars
            if char not in self.SIMILAR_CHARS
        )

        if not filtered:
            raise ValueError("Character group became empty after filtering.")

        return filtered