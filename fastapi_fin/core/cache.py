"""Framework-independent result cache policies for Interceptors."""

from collections.abc import Callable, Hashable
from threading import RLock
from time import monotonic

from attrs import define, field, frozen

from .errors import DeclarationError
from .types import (
    _normalize_optional_positive_integer,
    _normalize_optional_positive_number,
)

CacheKeyBuilder = Callable[[tuple[object, ...], dict[str, object]], Hashable]
CacheEntry = tuple[float | None, object]


def _default_key_builder(
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> Hashable:
    """Build a stable key from positional and keyword arguments."""
    return args, tuple(sorted(kwargs.items()))


def _normalize_key_builder(builder: CacheKeyBuilder) -> CacheKeyBuilder:
    if not callable(builder):
        raise DeclarationError("cache key_builder must be callable")
    return builder


@frozen(slots=True, kw_only=True)
class CachePolicy:
    """Immutable cache policy applied to one interceptor."""

    ttl: float | None = field(
        default=None,
        converter=_normalize_optional_positive_number,
    )
    max_entries: int | None = field(
        default=None,
        converter=_normalize_optional_positive_integer,
    )
    key_builder: CacheKeyBuilder = field(
        default=_default_key_builder,
        converter=_normalize_key_builder,
    )

    def build_key(
        self,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> Hashable:
        """Build and validate a hashable cache key at execution time."""
        key = self.key_builder(args, kwargs)
        try:
            hash(key)
        except TypeError as error:
            raise TypeError("cache key_builder must return a hashable value") from error
        return key


@define(slots=True)
class CacheStore:
    """Mutable execution-time cache shared by one compiled endpoint."""

    _entries: dict[str, dict[Hashable, CacheEntry]] = field(factory=dict)
    _lock: RLock = field(factory=RLock, init=False, repr=False, eq=False)

    def lookup(
        self,
        namespace: str,
        policy: CachePolicy,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> tuple[bool, object]:
        """Return whether a live value exists for an interceptor namespace."""
        with self._lock:
            key = policy.build_key(args, kwargs)
            namespace_entries = self._entries.setdefault(namespace, {})
            entry = namespace_entries.get(key)
            if entry is None:
                return False, None

            expires_at, value = entry
            if expires_at is not None and expires_at <= monotonic():
                del namespace_entries[key]
                return False, None
            return True, value

    def store(
        self,
        namespace: str,
        policy: CachePolicy,
        args: tuple[object, ...],
        kwargs: dict[str, object],
        value: object,
    ) -> None:
        """Store a successful result and evict the oldest entry if needed."""
        with self._lock:
            key = policy.build_key(args, kwargs)
            namespace_entries = self._entries.setdefault(namespace, {})
            if policy.max_entries is not None and key not in namespace_entries:
                while len(namespace_entries) >= policy.max_entries:
                    namespace_entries.pop(next(iter(namespace_entries)))
            expires_at = None if policy.ttl is None else monotonic() + policy.ttl
            namespace_entries[key] = (expires_at, value)

    def clear(self, namespace: str | None = None) -> None:
        """Clear all cached values or one interceptor namespace."""
        with self._lock:
            if namespace is None:
                self._entries.clear()
            else:
                self._entries.pop(namespace, None)
