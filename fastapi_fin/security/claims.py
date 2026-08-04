"""Immutable authenticated identity and validated JWT claims."""

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import cast

from attrs import define, field

from .errors import InvalidTokenError


def _normalize_text(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidTokenError(f"{label} must be non-empty")
    return value.strip()


def _normalize_optional_text(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_text(value, label)


def _normalize_texts(value: object, label: str, *, split: bool = False) -> tuple[str, ...]:
    if isinstance(value, str):
        values = tuple(value.split()) if split else (value,)
    else:
        if not isinstance(value, Iterable):
            raise InvalidTokenError(f"{label} must be a string or iterable of strings")
        try:
            values = tuple(value)
        except TypeError as error:
            raise InvalidTokenError(f"{label} must be a string or iterable of strings") from error
    if not values:
        raise InvalidTokenError(f"{label} must contain non-empty strings")
    normalized: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise InvalidTokenError(f"{label} must contain non-empty strings")
        normalized.append(item.strip())
    return tuple(dict.fromkeys(normalized))


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _normalize_claims(value: Mapping[str, object]) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InvalidTokenError("claims must be a mapping")
    return cast("Mapping[str, object]", _freeze(value))


def _normalize_optional_texts(
    value: object,
    label: str,
    *,
    split: bool = False,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        if not value.strip():
            return ()
        return _normalize_texts(value, label, split=split)
    if not isinstance(value, Iterable):
        raise InvalidTokenError(f"{label} must be a string or iterable of strings")
    try:
        values = tuple(value)
    except TypeError as error:
        raise InvalidTokenError(f"{label} must be a string or iterable of strings") from error
    if not values:
        return ()
    return _normalize_texts(values, label, split=split)


@define(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Validated identity material made available to application code."""

    subject: str = field(converter=lambda value: _normalize_text(value, "subject"))
    issuer: str = field(converter=lambda value: _normalize_text(value, "issuer"))
    audience: tuple[str, ...] = field(
        converter=lambda value: _normalize_texts(value, "audience"),
    )
    scopes: tuple[str, ...] = field(
        default=(),
        converter=lambda value: _normalize_optional_texts(value, "scopes", split=True),
    )
    roles: tuple[str, ...] = field(
        default=(),
        converter=lambda value: _normalize_optional_texts(value, "roles"),
    )
    token_id: str | None = field(
        default=None,
        converter=lambda value: _normalize_optional_text(value, "token_id"),
    )
    token_type: str | None = field(
        default=None,
        converter=lambda value: _normalize_optional_text(value, "token_type"),
    )
    claims: Mapping[str, object] = field(factory=dict, converter=_normalize_claims)

    def has_scope(self, scope: str) -> bool:
        """Return whether this principal has one exact scope."""
        return scope in self.scopes

    def has_role(self, role: str) -> bool:
        """Return whether this principal has one exact role."""
        return role in self.roles


__all__ = ["AuthenticatedPrincipal"]
