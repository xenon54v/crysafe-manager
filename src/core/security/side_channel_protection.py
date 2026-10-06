from __future__ import annotations

import hashlib
import hmac
import os
import random
import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from typing import Self


class SideChannelProtection:
    """Content-independent comparison helpers and optional software noise."""

    def __init__(
        self,
        *,
        jitter_max_ms: float = 0.0,
        algorithmic_noise: bool = False,
        sleep=time.sleep,
    ) -> None:
        if not 0.0 <= jitter_max_ms <= 25.0:
            raise ValueError("Jitter must be between 0 and 25 ms.")
        self.jitter_max_ms = jitter_max_ms
        self.algorithmic_noise = algorithmic_noise
        self._sleep = sleep
        self._noise_key = bytearray(os.urandom(32))

    @staticmethod
    def secure_compare(left: bytes | bytearray, right: bytes | bytearray) -> bool:
        """Compare fixed-size digests so the mismatch position is not observable."""
        left_bytes = bytes(left)
        right_bytes = bytes(right)
        left_digest = hashlib.sha256(
            len(left_bytes).to_bytes(8, "big") + left_bytes
        ).digest()
        right_digest = hashlib.sha256(
            len(right_bytes).to_bytes(8, "big") + right_bytes
        ).digest()
        return hmac.compare_digest(left_digest, right_digest)

    @classmethod
    def secure_string_compare(cls, left: str, right: str) -> bool:
        return cls.secure_compare(left.encode("utf-8"), right.encode("utf-8"))

    @staticmethod
    def constant_time_select(condition: bool, if_true: bytes, if_false: bytes) -> bytes:
        if len(if_true) != len(if_false):
            raise ValueError("Constant-time selection requires equal-length values.")
        mask = 0xFF * int(bool(condition))
        inverse = mask ^ 0xFF
        return bytes(
            (left & mask) | (right & inverse)
            for left, right in zip(if_true, if_false, strict=True)
        )

    @classmethod
    def constant_time_contains(cls, haystack: str, needle: str) -> bool:
        """Scan every candidate offset without returning on the first match."""
        source = haystack.encode("utf-8")
        target = needle.encode("utf-8")
        if not target:
            return True
        padded = source + (b"\x00" * len(target))
        candidates = max(1, len(source) - len(target) + 1)
        found = 0
        for offset in range(candidates):
            candidate = padded[offset : offset + len(target)]
            found |= int(hmac.compare_digest(candidate, target))
        return bool(found)

    def harden_operation(self) -> AbstractContextManager[None]:
        """Add optional blinding work around a cryptographic operation."""
        if not self.algorithmic_noise and not self.jitter_max_ms:
            return nullcontext()
        return self._hardened_operation()

    @contextmanager
    def _hardened_operation(self) -> Iterator[None]:
        self._run_noise_round()
        try:
            yield
        finally:
            self._run_noise_round()
            if self.jitter_max_ms:
                self._sleep(random.uniform(0.0, self.jitter_max_ms) / 1000.0)

    def clear(self) -> None:
        for index in range(len(self._noise_key)):
            self._noise_key[index] = 0
        self._noise_key.clear()

    def _run_noise_round(self) -> None:
        if not self.algorithmic_noise or not self._noise_key:
            return
        seed = os.urandom(32)
        digest = hmac.new(bytes(self._noise_key), seed, hashlib.sha256).digest()
        hmac.compare_digest(digest, digest)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args) -> None:
        self.clear()
