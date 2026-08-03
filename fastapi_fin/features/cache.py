"""Optional small in-process cache primitive."""

from collections.abc import Hashable
from dataclasses import dataclass
from math import isfinite
from threading import RLock
from time import monotonic

from ..errors import DefinitionError


@dataclass(frozen=True, slots=True)
class CachePolicy:
    ttl: float | None = None
    max_entries: int | None = None

    def __post_init__(self) -> None:
        if self.ttl is not None:
            if (
                isinstance(self.ttl, bool)
                or not isinstance(self.ttl, (int, float))
                or not isfinite(float(self.ttl))
                or self.ttl <= 0
            ):
                raise DefinitionError("cache ttl must be finite and positive")
            object.__setattr__(self, "ttl", float(self.ttl))
        if self.max_entries is not None and (
            isinstance(self.max_entries, bool)
            or not isinstance(self.max_entries, int)
            or self.max_entries <= 0
        ):
            raise DefinitionError("cache max_entries must be positive")


class CacheStore:
    """Thread-safe cache state kept outside immutable application definitions."""

    def __init__(self, policy: CachePolicy | None = None) -> None:
        self.policy = CachePolicy() if policy is None else policy
        self._values: dict[Hashable, tuple[float, object]] = {}
        self._lock = RLock()

    def get(self, key: Hashable) -> object | None:
        _ensure_hashable(key)
        now = monotonic()
        with self._lock:
            item = self._values.get(key)
            if item is None:
                return None
            expires_at, value = item
            if expires_at and expires_at <= now:
                del self._values[key]
                return None
            return value

    def set(self, key: Hashable, value: object) -> None:
        _ensure_hashable(key)
        now = monotonic()
        expires_at = now + self.policy.ttl if self.policy.ttl is not None else 0.0
        with self._lock:
            self._values[key] = (expires_at, value)
            if self.policy.max_entries is not None:
                while len(self._values) > self.policy.max_entries:
                    self._values.pop(next(iter(self._values)))

    def clear(self) -> None:
        with self._lock:
            self._values.clear()


def _ensure_hashable(key: Hashable) -> None:
    try:
        hash(key)
    except TypeError as error:
        raise DefinitionError("cache key must be hashable") from error


__all__ = ["CachePolicy", "CacheStore"]
