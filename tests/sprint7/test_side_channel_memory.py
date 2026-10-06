from __future__ import annotations

import statistics
import time

import pytest

from src.core.crypto.key_storage import KeyStorage
from src.core.security import MemoryGuard, ProtectedMemory, SideChannelProtection


def _timed_comparisons(left: bytes, right: bytes, repetitions: int = 2_000) -> int:
    started = time.perf_counter_ns()
    for _ in range(repetitions):
        SideChannelProtection.secure_compare(left, right)
    return time.perf_counter_ns() - started


def test_secure_compare_does_not_reveal_mismatch_position():
    left = b"A" * 64
    candidates = (
        b"B" + (b"A" * 63),
        (b"A" * 31) + b"B" + (b"A" * 32),
        (b"A" * 63) + b"B",
    )
    medians = [
        statistics.median(_timed_comparisons(left, candidate) for _ in range(7))
        for candidate in candidates
    ]

    assert max(medians) / min(medians) < 1.35
    assert not any(
        SideChannelProtection.secure_compare(left, candidate)
        for candidate in candidates
    )


def test_constant_time_helpers_scan_and_select_without_early_result():
    protection = SideChannelProtection()

    assert protection.constant_time_contains("alpha beta gamma", "beta")
    assert not protection.constant_time_contains("alpha beta gamma", "delta")
    assert protection.constant_time_select(True, b"yes", b"no!") == b"yes"
    assert protection.constant_time_select(False, b"yes", b"no!") == b"no!"
    with pytest.raises(ValueError):
        protection.constant_time_select(True, b"short", b"longer")


def test_protected_memory_uses_canaries_guard_pages_and_explicit_wipe():
    block = ProtectedMemory.from_bytes(
        b"memory-guard-test", lock_memory=True, guard_pages=True, wipe_passes=2
    )

    assert block.read() == b"memory-guard-test"
    assert block.status.canaries_valid
    assert block.status.guard_pages_active
    block.wipe()
    assert block.read() == b"\x00" * len(b"memory-guard-test")
    block.close()
    assert block.closed


def test_protected_secret_dump_regions_do_not_contain_plaintext():
    secret = b"Sprint7-memory-dump-marker-7f93b2"
    guard = MemoryGuard(lock_memory=True, guard_pages=True, wipe_passes=2)
    protected = guard.protect(secret)

    assert protected.read() == secret
    assert not protected.contains_plaintext(secret)
    assert protected.status.canaries_valid
    assert protected.status.guard_pages_active

    assert guard.wipe_all() == 1
    assert protected.closed
    assert guard.active_allocations == 0


def test_key_storage_retains_only_masked_key_material():
    key = b"Unique-Sprint7-Key-Marker-32!!"[:32]
    storage = KeyStorage(ttl_seconds=60)
    storage.save(key)

    assert storage.load() == key
    assert storage._cached_key is not None
    assert not storage._cached_key.contains_plaintext(key)
    assert storage.protection_status.canaries_valid

    storage.clear()
    assert not storage.has_key()


def test_bulk_protected_allocation_has_less_than_five_percent_overhead():
    payload = b"P" * (1024 * 1024)
    guard = MemoryGuard(lock_memory=False, guard_pages=True)
    protected = guard.protect(payload)
    overhead = (protected.allocated_bytes - len(payload)) / len(payload)

    assert overhead < 0.05
    protected.close()
