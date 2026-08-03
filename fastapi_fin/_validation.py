"""Internal validation helpers shared by immutable definition models."""

from collections.abc import Callable, Iterable, Mapping
from types import MappingProxyType
from typing import Any

from .errors import DefinitionError

AttrsValidator = Callable[[object, Any, object], None]


def normalize_iterable[ValueT](value: Iterable[ValueT], label: str) -> tuple[ValueT, ...]:
    """Materialize a public iterable and translate invalid inputs consistently."""
    try:
        return tuple(value)
    except TypeError as error:
        raise DefinitionError(f"{label} must be iterable") from error


def callable_validator(label: str) -> AttrsValidator:
    """Build an attrs validator for callable public values."""

    def validate(_instance: object, _attribute: Any, value: object) -> None:
        if not callable(value):
            raise DefinitionError(f"{label} must be callable")

    return validate


def optional_callable_validator(label: str) -> AttrsValidator:
    """Build an attrs validator for optional callable public values."""

    def validate(_instance: object, _attribute: Any, value: object) -> None:
        if value is not None and not callable(value):
            raise DefinitionError(f"{label} must be callable")

    return validate


def bool_validator(label: str) -> AttrsValidator:
    """Build an attrs validator for strict bool values."""

    def validate(_instance: object, _attribute: Any, value: object) -> None:
        if not isinstance(value, bool):
            raise DefinitionError(f"{label} must be bool")

    return validate


def integer_validator(label: str) -> AttrsValidator:
    """Build an attrs validator for integers without accepting bool."""

    def validate(_instance: object, _attribute: Any, value: object) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise DefinitionError(f"{label} must be an integer")

    return validate


def non_empty_text_validator(label: str) -> AttrsValidator:
    """Build an attrs validator for non-empty text values."""

    def validate(_instance: object, _attribute: Any, value: object) -> None:
        if not isinstance(value, str) or not value.strip():
            raise DefinitionError(f"{label} must be non-empty text")

    return validate


def optional_non_empty_text_validator(label: str) -> AttrsValidator:
    """Build an attrs validator for optional non-empty text values."""

    def validate(_instance: object, _attribute: Any, value: object) -> None:
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise DefinitionError(f"{label} must be non-empty text")

    return validate


def instance_validator(expected: type[object], label: str) -> AttrsValidator:
    """Build an attrs validator for one specific public model type."""

    def validate(_instance: object, _attribute: Any, value: object) -> None:
        if not isinstance(value, expected):
            raise DefinitionError(f"{label} must be a {expected.__name__}")

    return validate


def immutable_mapping(value: Mapping[str, object], label: str) -> Mapping[str, object]:
    """Copy a mapping into a read-only snapshot."""
    if not isinstance(value, Mapping):
        raise DefinitionError(f"{label} must be a mapping")
    return MappingProxyType(dict(value))


__all__ = [
    "bool_validator",
    "callable_validator",
    "immutable_mapping",
    "instance_validator",
    "integer_validator",
    "non_empty_text_validator",
    "normalize_iterable",
    "optional_callable_validator",
    "optional_non_empty_text_validator",
]
