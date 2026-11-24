"""Internal validation helpers shared by immutable definition models."""

from collections.abc import Callable, Iterable

from .errors import DefinitionError

AttrsValidator = Callable[[object, object, object], None]


def normalize_iterable[ValueT](value: Iterable[ValueT], label: str) -> tuple[ValueT, ...]:
    """Materialize a public iterable and translate invalid inputs consistently."""
    try:
        return tuple(value)
    except TypeError as error:
        raise DefinitionError(f"{label} must be iterable") from error


def bool_validator(label: str) -> AttrsValidator:
    """Build an attrs validator for strict bool values."""

    def validate(_instance: object, _attribute: object, value: object) -> None:
        if not isinstance(value, bool):
            raise DefinitionError(f"{label} must be bool")

    return validate


__all__ = ["bool_validator", "normalize_iterable"]
