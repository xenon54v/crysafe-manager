from __future__ import annotations

import math
import re
import secrets
import string
import threading
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordStrength:
    score: int
    entropy_bits: float
    label: str


class PasswordStrengthAnalyzer:
    """Small offline strength estimator used in place of a network service."""

    COMMON_FRAGMENTS = (
        "password",
        "qwerty",
        "admin",
        "letmein",
        "welcome",
        "123456",
    )

    def analyze(self, password: str) -> PasswordStrength:
        entropy = self.estimate_entropy(password)
        lowered = password.casefold()

        if not password or any(
            fragment in lowered for fragment in self.COMMON_FRAGMENTS
        ):
            return PasswordStrength(0, entropy, "Very weak")

        if entropy < 28:
            score = 0
        elif entropy < 36:
            score = 1
        elif entropy < 48:
            score = 2
        elif entropy < 70:
            score = 3
        else:
            score = 4

        if re.search(r"(.)\1{2,}", password):
            score = max(0, score - 1)
        if self._contains_sequence(lowered):
            score = max(0, score - 1)

        labels = ("Very weak", "Weak", "Fair", "Strong", "Very strong")
        return PasswordStrength(score, entropy, labels[score])

    def estimate_entropy(self, password: str) -> float:
        pool_size = 0
        if any(character.islower() for character in password):
            pool_size += 26
        if any(character.isupper() for character in password):
            pool_size += 26
        if any(character.isdigit() for character in password):
            pool_size += 10
        if any(character in PasswordGenerator.SYMBOLS for character in password):
            pool_size += len(PasswordGenerator.SYMBOLS)

        return len(password) * math.log2(pool_size) if pool_size else 0.0

    @staticmethod
    def _contains_sequence(password: str) -> bool:
        sequences = (string.ascii_lowercase, string.digits)
        reversed_sequences = tuple(value[::-1] for value in sequences)
        return any(
            password[index : index + 4] in sequence
            for index in range(max(0, len(password) - 3))
            for sequence in sequences + reversed_sequences
        )


class PasswordGenerator:
    DEFAULT_LENGTH = 16
    MIN_LENGTH = 8
    MAX_LENGTH = 64
    HISTORY_SIZE = 20
    AMBIGUOUS_CHARACTERS = frozenset("lI10O")
    SYMBOLS = "!@#$%^&*"

    def __init__(
        self, strength_analyzer: PasswordStrengthAnalyzer | None = None
    ) -> None:
        self.strength_analyzer = strength_analyzer or PasswordStrengthAnalyzer()
        self._history: deque[str] = deque(maxlen=self.HISTORY_SIZE)
        self._history_lock = threading.Lock()

    def generate(
        self,
        length: int = DEFAULT_LENGTH,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = True,
        **legacy_options,
    ) -> str:
        if "use_special" in legacy_options:
            use_symbols = bool(legacy_options.pop("use_special"))
        if "exclude_similar" in legacy_options:
            exclude_ambiguous = bool(legacy_options.pop("exclude_similar"))
        if legacy_options:
            option = next(iter(legacy_options))
            raise TypeError(f"Unknown password option: {option}")

        self._validate_length(length)
        groups = self._build_groups(
            use_uppercase,
            use_lowercase,
            use_digits,
            use_symbols,
            exclude_ambiguous,
        )
        if len(groups) > length:
            raise ValueError(
                "Password length is too short for selected character sets."
            )

        for _ in range(128):
            password = self._generate_candidate(length, groups)
            if self.strength_analyzer.analyze(password).score < 3:
                continue

            with self._history_lock:
                if password in self._history:
                    continue
                self._history.append(password)
            return password

        raise ValueError(
            "Selected settings cannot produce a sufficiently strong password."
        )

    def estimate_entropy(self, password: str) -> float:
        return self.strength_analyzer.estimate_entropy(password)

    def strength(self, password: str) -> PasswordStrength:
        return self.strength_analyzer.analyze(password)

    def clear_history(self) -> None:
        with self._history_lock:
            self._history.clear()

    def recent_passwords(self) -> tuple[str, ...]:
        with self._history_lock:
            return tuple(self._history)

    def _generate_candidate(self, length: int, groups: list[str]) -> str:
        characters = [secrets.choice(group) for group in groups]
        combined = "".join(groups)
        characters.extend(secrets.choice(combined) for _ in range(length - len(groups)))

        for index in range(len(characters) - 1, 0, -1):
            swap_index = secrets.randbelow(index + 1)
            characters[index], characters[swap_index] = (
                characters[swap_index],
                characters[index],
            )
        return "".join(characters)

    def _build_groups(
        self,
        use_uppercase: bool,
        use_lowercase: bool,
        use_digits: bool,
        use_symbols: bool,
        exclude_ambiguous: bool,
    ) -> list[str]:
        candidates = (
            (use_uppercase, string.ascii_uppercase),
            (use_lowercase, string.ascii_lowercase),
            (use_digits, string.digits),
            (use_symbols, self.SYMBOLS),
        )
        groups = [characters for enabled, characters in candidates if enabled]
        if not groups:
            raise ValueError("At least one character set must be selected.")

        if exclude_ambiguous:
            groups = [
                "".join(
                    character
                    for character in characters
                    if character not in self.AMBIGUOUS_CHARACTERS
                )
                for characters in groups
            ]
        if any(not group for group in groups):
            raise ValueError("A selected character set is empty.")
        return groups

    def _validate_length(self, length: int) -> None:
        if isinstance(length, bool) or not isinstance(length, int):
            raise TypeError("Password length must be an integer.")
        if not self.MIN_LENGTH <= length <= self.MAX_LENGTH:
            raise ValueError(
                f"Password length must be between {self.MIN_LENGTH} and {self.MAX_LENGTH}."
            )
