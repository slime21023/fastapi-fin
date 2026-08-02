from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, cast

import pytest

from fastapi_fin.core import CachePolicy, CacheStore, DeclarationError

if TYPE_CHECKING:
    from fastapi_fin.core.cache import CacheKeyBuilder


def test_cache_store_evicts_oldest_entry() -> None:
    policy = CachePolicy(max_entries=1)
    store = CacheStore()

    store.store("items", policy, (1,), {}, "one")
    assert store.lookup("items", policy, (1,), {}) == (True, "one")

    store.store("items", policy, (2,), {}, "two")

    assert store.lookup("items", policy, (1,), {}) == (False, None)
    assert store.lookup("items", policy, (2,), {}) == (True, "two")


def test_cache_store_expires_entries_after_ttl(monkeypatch) -> None:
    moments = iter((0.0, 0.5, 1.0))
    monkeypatch.setattr("fastapi_fin.core.cache.monotonic", lambda: next(moments))
    policy = CachePolicy(ttl=1.0)
    store = CacheStore()

    store.store("items", policy, (), {}, "value")

    assert store.lookup("items", policy, (), {}) == (True, "value")
    assert store.lookup("items", policy, (), {}) == (False, None)


def test_cache_policy_rejects_unhashable_keys_and_invalid_builders() -> None:
    with pytest.raises(DeclarationError):
        CachePolicy(key_builder=cast("CacheKeyBuilder", object()))

    policy = CachePolicy(key_builder=cast("CacheKeyBuilder", lambda _args, _kwargs: []))
    with pytest.raises(TypeError, match="hashable"):
        policy.build_key((), {})


def test_cache_store_supports_concurrent_sync_access() -> None:
    policy = CachePolicy(max_entries=128)
    store = CacheStore()

    def write_and_read(value: int) -> tuple[bool, object]:
        store.store("concurrent", policy, (value,), {}, value)
        return store.lookup("concurrent", policy, (value,), {})

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(write_and_read, range(64)))

    assert results == [(True, value) for value in range(64)]
