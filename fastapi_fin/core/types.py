"""Shared, framework-independent types and input normalization."""

from collections.abc import Iterable
from enum import StrEnum
from math import isfinite

from .errors import DeclarationError


def _attribute_name(attribute: object) -> str:
    return str(getattr(attribute, "name", "value"))


def _validate_integer(_instance: object, attribute: object, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{_attribute_name(attribute)} must be an integer")


def _validate_nonnegative_integer(
    _instance: object,
    attribute: object,
    value: object,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{_attribute_name(attribute)} must be an integer")
    if value < 0:
        raise ValueError(f"{_attribute_name(attribute)} must be non-negative")


def _normalize_optional_positive_integer(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("value must be an integer")
    if value <= 0:
        raise ValueError("value must be positive")
    return value


def _normalize_optional_positive_number(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("value must be a number")
    if value <= 0 or (isinstance(value, float) and not isfinite(value)):
        raise ValueError("value must be finite and positive")
    return float(value)


class HttpMethod(StrEnum):
    """HTTP methods supported by route metadata."""

    CONNECT = "CONNECT"
    DELETE = "DELETE"
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH = "PATCH"
    POST = "POST"
    PUT = "PUT"
    TRACE = "TRACE"


class Scope(StrEnum):
    """Supported dependency lifecycles."""

    SINGLETON = "singleton"
    TRANSIENT = "transient"
    REQUEST = "request"


def normalize_path(path: str) -> str:
    """Normalize and validate a route path at declaration time."""
    if not isinstance(path, str):
        raise DeclarationError("route path must be a string")

    normalized = path.strip()
    if not normalized:
        raise DeclarationError("route path must not be empty")
    if any(character.isspace() for character in normalized):
        raise DeclarationError(f"route path contains whitespace: {path!r}")
    if "?" in normalized or "#" in normalized:
        raise DeclarationError(f"route path must not contain a query or fragment: {path!r}")
    if "\x00" in normalized:
        raise DeclarationError("route path must not contain a null character")

    return f"/{normalized.lstrip('/')}"


def normalize_methods(
    methods: str | HttpMethod | Iterable[str | HttpMethod],
) -> tuple[HttpMethod, ...]:
    """Normalize method names and reject duplicates or unsupported values."""
    if isinstance(methods, (str, HttpMethod)):
        values = (methods,)
    else:
        try:
            values = tuple(methods)
        except TypeError as error:
            raise DeclarationError("HTTP methods must be iterable") from error

    if not values:
        raise DeclarationError("at least one HTTP method is required")

    normalized: list[HttpMethod] = []
    for value in values:
        try:
            method = value if isinstance(value, HttpMethod) else HttpMethod(value.upper())
        except (AttributeError, TypeError, ValueError) as error:
            raise DeclarationError(f"unsupported HTTP method: {value!r}") from error
        if method not in normalized:
            normalized.append(method)

    return tuple(normalized)


def join_paths(prefix: str, path: str) -> str:
    """Join two normalized route path segments."""
    normalized_prefix = normalize_path(prefix)
    normalized_path = normalize_path(path)
    if normalized_prefix == "/":
        return normalized_path
    return normalize_path(f"{normalized_prefix.rstrip('/')}/{normalized_path.lstrip('/')}")
