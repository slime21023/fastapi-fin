"""Immutable authenticated identity and validated JWT claims."""

from collections.abc import Callable, Iterable, Mapping
from types import MappingProxyType
from typing import cast

from attrs import define, field

from .._validation import optional_text_converter, text_converter
from .errors import InvalidTokenError


def _text_items(value: object, label: str, *, split: bool) -> tuple[object, ...]:
    """Read a string (optionally whitespace-separated) or an iterable into a tuple."""
    if isinstance(value, str):
        return tuple(value.split()) if split else (value,)
    if not isinstance(value, Iterable):
        raise InvalidTokenError(f"{label} must be a string or iterable of strings")
    return tuple(value)


def _normalize_texts(items: tuple[object, ...], label: str) -> tuple[str, ...]:
    texts = [item.strip() for item in items if isinstance(item, str)]
    if not items or len(texts) != len(items) or not all(texts):
        raise InvalidTokenError(f"{label} must contain non-empty strings")
    return tuple(dict.fromkeys(texts))


def _required_texts(label: str) -> Callable[[object], tuple[str, ...]]:
    def convert(value: object) -> tuple[str, ...]:
        return _normalize_texts(_text_items(value, label, split=False), label)

    return convert


def _optional_texts(label: str, *, split: bool = False) -> Callable[[object], tuple[str, ...]]:
    """Build a converter where ``None``, blank text and empty iterables mean "none"."""

    def convert(value: object) -> tuple[str, ...]:
        if value is None or (isinstance(value, str) and not value.strip()):
            return ()
        items = _text_items(value, label, split=split)
        return _normalize_texts(items, label) if items else ()

    return convert


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _normalize_claims(value: Mapping[str, object]) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InvalidTokenError("claims must be a mapping")
    return cast("Mapping[str, object]", _freeze(value))


@define(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Validated identity material made available to application code."""

    subject: str = field(converter=text_converter("subject", error=InvalidTokenError))
    issuer: str = field(converter=text_converter("issuer", error=InvalidTokenError))
    audience: tuple[str, ...] = field(converter=_required_texts("audience"))
    scopes: tuple[str, ...] = field(default=(), converter=_optional_texts("scopes", split=True))
    roles: tuple[str, ...] = field(default=(), converter=_optional_texts("roles"))
    token_id: str | None = field(
        default=None, converter=optional_text_converter("token_id", error=InvalidTokenError)
    )
    token_type: str | None = field(
        default=None, converter=optional_text_converter("token_type", error=InvalidTokenError)
    )
    claims: Mapping[str, object] = field(factory=dict, converter=_normalize_claims)

    def has_scope(self, scope: str) -> bool:
        """Return whether this principal has one exact scope."""
        return scope in self.scopes

    def has_role(self, role: str) -> bool:
        """Return whether this principal has one exact role."""
        return role in self.roles


__all__ = ["AuthenticatedPrincipal"]
