from __future__ import annotations

import ctypes
import hashlib
import mmap
import os
import secrets
import sys
import threading
import weakref
from dataclasses import dataclass
from typing import Self


class MemoryProtectionError(RuntimeError):
    """Raised when a protected memory block cannot be used safely."""


@dataclass(frozen=True)
class ProtectionStatus:
    """Represent protection status behavior."""

    platform: str
    memory_locked: bool
    map_locked_requested: bool
    guard_pages_active: bool
    canaries_valid: bool


class ProtectedMemory:
    """Page-aligned secret storage with locking, guard pages, and canaries."""

    CANARY_SIZE = 32

    def __init__(
        self,
        size: int,
        *,
        lock_memory: bool = True,
        guard_pages: bool = True,
        wipe_passes: int = 1,
    ) -> None:
        if not 1 <= size <= 16 * 1024 * 1024:
            raise ValueError("Protected allocation must be between 1 byte and 16 MiB.")
        if wipe_passes not in {1, 2, 3}:
            raise ValueError("Wipe passes must be 1, 2, or 3.")
        self.size = size
        self._wipe_passes = wipe_passes
        self._page_size = mmap.PAGESIZE
        requested = size + (2 * self.CANARY_SIZE)
        self._payload_pages = (
            (requested + self._page_size - 1) // self._page_size
        ) * self._page_size
        self._total_size = self._payload_pages + (2 * self._page_size)
        self._map_locked_requested = False
        self._map = self._allocate_map(self._total_size, lock_memory)
        self._base_reference = ctypes.c_ubyte.from_buffer(self._map)
        self._base_address = ctypes.addressof(self._base_reference)
        self._payload_address = self._base_address + self._page_size
        self._data_address = self._payload_address + self.CANARY_SIZE
        self._prefix_canary = secrets.token_bytes(self.CANARY_SIZE)
        self._suffix_canary = secrets.token_bytes(self.CANARY_SIZE)
        self._guard_pages_active = False
        self._closed = False
        self._mutex = threading.RLock()

        ctypes.memmove(self._payload_address, self._prefix_canary, self.CANARY_SIZE)
        ctypes.memmove(
            self._data_address + self.size,
            self._suffix_canary,
            self.CANARY_SIZE,
        )
        self._memory_locked = self._lock_payload() if lock_memory else False
        if guard_pages:
            self._guard_pages_active = self._set_guard_pages(no_access=True)

    @classmethod
    def from_bytes(cls, value: bytes | bytearray, **options) -> ProtectedMemory:
        if not value:
            raise ValueError("Protected memory value must not be empty.")
        block = cls(len(value), **options)
        block.write(value)
        return block

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def allocated_bytes(self) -> int:
        return self._total_size

    @property
    def status(self) -> ProtectionStatus:
        return ProtectionStatus(
            platform=sys.platform,
            memory_locked=self._memory_locked,
            map_locked_requested=self._map_locked_requested,
            guard_pages_active=self._guard_pages_active,
            canaries_valid=self.check_canaries() if not self.closed else True,
        )

    def write(self, value: bytes | bytearray) -> None:
        raw = bytes(value)
        if len(raw) > self.size:
            raise ValueError("Secret does not fit in the protected allocation.")
        with self._mutex:
            self._ensure_open()
            ctypes.memset(self._data_address, 0, self.size)
            ctypes.memmove(self._data_address, raw, len(raw))

    def read(self) -> bytearray:
        with self._mutex:
            self._ensure_open()
            self._ensure_canaries()
            return bytearray(ctypes.string_at(self._data_address, self.size))

    def contains_plaintext(self, value: bytes | str) -> bool:
        needle = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        with self._mutex:
            self._ensure_open()
            return needle in ctypes.string_at(
                self._payload_address, self._payload_pages
            )

    def check_canaries(self) -> bool:
        if self.closed:
            return True
        prefix = ctypes.string_at(self._payload_address, self.CANARY_SIZE)
        suffix = ctypes.string_at(self._data_address + self.size, self.CANARY_SIZE)
        return secrets.compare_digest(
            prefix, self._prefix_canary
        ) and secrets.compare_digest(suffix, self._suffix_canary)

    def wipe(self) -> None:
        with self._mutex:
            if self.closed:
                return
            self._ensure_canaries()
            for _pass in range(self._wipe_passes - 1):
                random_data = os.urandom(self.size)
                ctypes.memmove(self._data_address, random_data, self.size)
            ctypes.memset(self._data_address, 0, self.size)

    def close(self) -> None:
        with self._mutex:
            if self.closed:
                return
            try:
                self.wipe()
            finally:
                if self._guard_pages_active:
                    self._set_guard_pages(no_access=False)
                if self._memory_locked:
                    self._unlock_payload()
                ctypes.memset(self._payload_address, 0, self._payload_pages)
                self._closed = True
                del self._base_reference
                self._map.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001 - destructors must not raise
            return

    def _allocate_map(self, total_size: int, lock_memory: bool):
        if os.name == "posix":
            flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
            map_locked = getattr(mmap, "MAP_LOCKED", 0)
            if lock_memory and map_locked:
                try:
                    result = mmap.mmap(
                        -1,
                        total_size,
                        flags=flags | map_locked,
                        prot=mmap.PROT_READ | mmap.PROT_WRITE,
                    )
                    self._map_locked_requested = True
                    return result
                except (OSError, ValueError):
                    pass
            return mmap.mmap(
                -1,
                total_size,
                flags=flags,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
        return mmap.mmap(-1, total_size, access=mmap.ACCESS_WRITE)

    def _lock_payload(self) -> bool:
        try:
            if sys.platform == "win32":
                return bool(
                    ctypes.windll.kernel32.VirtualLock(
                        ctypes.c_void_p(self._payload_address),
                        ctypes.c_size_t(self._payload_pages),
                    )
                )
            libc = ctypes.CDLL(None, use_errno=True)
            return (
                libc.mlock(
                    ctypes.c_void_p(self._payload_address),
                    ctypes.c_size_t(self._payload_pages),
                )
                == 0
            )
        except (AttributeError, OSError, TypeError):
            return False

    def _unlock_payload(self) -> None:
        try:
            if sys.platform == "win32":
                ctypes.windll.kernel32.VirtualUnlock(
                    ctypes.c_void_p(self._payload_address),
                    ctypes.c_size_t(self._payload_pages),
                )
            else:
                libc = ctypes.CDLL(None, use_errno=True)
                libc.munlock(
                    ctypes.c_void_p(self._payload_address),
                    ctypes.c_size_t(self._payload_pages),
                )
        except (AttributeError, OSError, TypeError):
            return

    def _set_guard_pages(self, *, no_access: bool) -> bool:
        try:
            addresses = (
                self._base_address,
                self._base_address + self._page_size + self._payload_pages,
            )
            if sys.platform == "win32":
                protection = 0x01 if no_access else 0x04
                for address in addresses:
                    old = ctypes.c_ulong()
                    if not ctypes.windll.kernel32.VirtualProtect(
                        ctypes.c_void_p(address),
                        ctypes.c_size_t(self._page_size),
                        protection,
                        ctypes.byref(old),
                    ):
                        return False
                return True
            libc = ctypes.CDLL(None, use_errno=True)
            protection = 0 if no_access else mmap.PROT_READ | mmap.PROT_WRITE
            return all(
                libc.mprotect(
                    ctypes.c_void_p(address),
                    ctypes.c_size_t(self._page_size),
                    protection,
                )
                == 0
                for address in addresses
            )
        except (AttributeError, OSError, TypeError):
            return False

    def _ensure_open(self) -> None:
        if self.closed:
            raise MemoryProtectionError("Protected memory has already been released.")

    def _ensure_canaries(self) -> None:
        if not self.check_canaries():
            raise MemoryProtectionError("Protected memory canary check failed.")


class ProtectedSecret:
    """Keeps a random seed and masked bytes in one protected allocation."""

    SEED_SIZE = 32

    def __init__(
        self,
        value: bytes | bytearray,
        *,
        lock_memory: bool = True,
        guard_pages: bool = True,
        wipe_passes: int = 1,
    ) -> None:
        if not value:
            raise ValueError("Protected secret must not be empty.")
        self._closed = True
        self._lock = threading.RLock()
        raw = bytearray(value)
        seed = bytearray(secrets.token_bytes(self.SEED_SIZE))
        mask = bytearray(hashlib.shake_256(seed).digest(len(raw)))
        masked = bytearray(left ^ right for left, right in zip(raw, mask, strict=True))
        encoded = seed + masked
        options = {
            "lock_memory": lock_memory,
            "guard_pages": guard_pages,
            "wipe_passes": wipe_passes,
        }
        try:
            self._storage = ProtectedMemory.from_bytes(encoded, **options)
        finally:
            self._zero_bytearray(raw)
            self._zero_bytearray(seed)
            self._zero_bytearray(mask)
            self._zero_bytearray(masked)
            self._zero_bytearray(encoded)
        self.size = len(value)
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def status(self) -> ProtectionStatus:
        return self._storage.status

    @property
    def allocated_bytes(self) -> int:
        return self._storage.allocated_bytes

    def read(self) -> bytearray:
        with self._lock:
            self._ensure_open()
            encoded = self._storage.read()
            seed = encoded[: self.SEED_SIZE]
            masked = encoded[self.SEED_SIZE :]
            mask = bytearray(hashlib.shake_256(seed).digest(self.size))
            try:
                return bytearray(
                    left ^ right for left, right in zip(masked, mask, strict=True)
                )
            finally:
                self._zero_bytearray(encoded)
                self._zero_bytearray(seed)
                self._zero_bytearray(mask)
                self._zero_bytearray(masked)

    def contains_plaintext(self, value: bytes | str) -> bool:
        """Inspect both protected regions without reconstructing the secret."""
        with self._lock:
            self._ensure_open()
            return self._storage.contains_plaintext(value)

    def close(self) -> None:
        with self._lock:
            if self.closed:
                return
            self._storage.close()
            self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            if hasattr(self, "_lock"):
                self.close()
        except Exception:  # noqa: BLE001 - destructors must not raise
            return

    def _ensure_open(self) -> None:
        if self.closed:
            raise MemoryProtectionError("Protected secret has already been released.")

    @staticmethod
    def _zero_bytearray(value: bytearray) -> None:
        if value:
            ctypes.memset(
                (ctypes.c_ubyte * len(value)).from_buffer(value),
                0,
                len(value),
            )


class MemoryGuard:
    """Tracks protected allocations so panic and lock can wipe them together."""

    def __init__(
        self,
        *,
        lock_memory: bool = True,
        guard_pages: bool = True,
        wipe_passes: int = 1,
    ) -> None:
        self.lock_memory = lock_memory
        self.guard_pages = guard_pages
        self.wipe_passes = wipe_passes
        self._allocations: weakref.WeakSet[ProtectedMemory | ProtectedSecret] = (
            weakref.WeakSet()
        )
        self._lock = threading.RLock()

    def allocate(self, size: int) -> ProtectedMemory:
        block = ProtectedMemory(
            size,
            lock_memory=self.lock_memory,
            guard_pages=self.guard_pages,
            wipe_passes=self.wipe_passes,
        )
        with self._lock:
            self._allocations.add(block)
        return block

    def protect(self, value: bytes | bytearray) -> ProtectedSecret:
        secret = ProtectedSecret(
            value,
            lock_memory=self.lock_memory,
            guard_pages=self.guard_pages,
            wipe_passes=self.wipe_passes,
        )
        with self._lock:
            self._allocations.add(secret)
        return secret

    def wipe_all(self) -> int:
        with self._lock:
            blocks = tuple(self._allocations)
        wiped = 0
        for block in blocks:
            try:
                block.close()
                wiped += 1
            except Exception:  # noqa: BLE001, S112 - emergency cleanup continues
                continue
        with self._lock:
            self._allocations.clear()
        return wiped

    @property
    def active_allocations(self) -> int:
        with self._lock:
            return sum(not block.closed for block in self._allocations)
