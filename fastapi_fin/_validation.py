"""Internal validation helpers shared by immutable definition models."""

from collections.abc import Callable, Iterable

from .errors import DefinitionError, FastAPIFinError

type AttrsValidator = Callable[[object, object, object], None]
# A hashable type hint, such as a Protocol or class, that names a service.
type Contract = object
type ModuleName = str


def normalize_iterable[ValueT](value: Iterable[ValueT], label: str) -> tuple[ValueT, ...]:
    """Materialize a public iterable and translate invalid inputs consistently."""
    try:
        return tuple(value)
    except TypeError as error:
        raise DefinitionError(f"{label} must be iterable") from error


def tuple_converter[ValueT](label: str) -> Callable[[Iterable[ValueT]], tuple[ValueT, ...]]:
    """Build an attrs converter that snapshots an iterable into a tuple."""

    def convert(value: Iterable[ValueT]) -> tuple[ValueT, ...]:
        return normalize_iterable(value, label)

    return convert


def normalize_contract(value: Contract) -> Contract:
    """Accept only hashable type hints as dependency contracts."""
    if isinstance(value, str) or value is None:
        raise DefinitionError("contracts must be type hints, not strings or None")
    try:
        hash(value)
    except TypeError as error:
        raise DefinitionError("contracts must be hashable type hints") from error
    return value


def normalize_text(
    value: object, label: str, *, error: type[FastAPIFinError] = DefinitionError
) -> str:
    """Return stripped non-empty text or raise ``error`` naming ``label``."""
    if not isinstance(value, str) or not value.strip():
        raise error(f"{label} must be non-empty text")
    return value.strip()


def text_converter(
    label: str, *, error: type[FastAPIFinError] = DefinitionError
) -> Callable[[object], str]:
    """Build an attrs converter for required non-empty text."""

    def convert(value: object) -> str:
        return normalize_text(value, label, error=error)

    return convert


def optional_text_converter(
    label: str, *, error: type[FastAPIFinError] = DefinitionError
) -> Callable[[object], str | None]:
    """Build an attrs converter for text that may be ``None``."""

    def convert(value: object) -> str | None:
        return None if value is None else normalize_text(value, label, error=error)

    return convert


def normalize_text_tuple(
    values: Iterable[object] | str,
    label: str,
    *,
    allow_empty: bool = True,
    error: type[FastAPIFinError] = DefinitionError,
) -> tuple[str, ...]:
    """Strip and de-duplicate non-empty strings; a lone string counts as one item."""
    items = (values,) if isinstance(values, str) else normalize_iterable(values, label)
    texts = [item.strip() for item in items if isinstance(item, str)]
    if len(texts) != len(items) or not all(texts):
        raise error(f"{label} must contain non-empty strings")
    normalized = tuple(dict.fromkeys(texts))
    if not normalized and not allow_empty:
        raise error(f"{label} must contain non-empty strings")
    return normalized


def text_tuple_converter(
    label: str, *, allow_empty: bool = True
) -> Callable[[Iterable[str] | str], tuple[str, ...]]:
    """Build an attrs converter around :func:`normalize_text_tuple`."""

    def convert(values: Iterable[str] | str) -> tuple[str, ...]:
        return normalize_text_tuple(values, label, allow_empty=allow_empty)

    return convert


def bool_validator(label: str) -> AttrsValidator:
    """Build an attrs validator for strict bool values."""

    def validate(_instance: object, _attribute: object, value: object) -> None:
        if not isinstance(value, bool):
            raise DefinitionError(f"{label} must be bool")

    return validate


__all__ = [
    "bool_validator",
    "normalize_contract",
    "normalize_iterable",
    "normalize_text",
    "normalize_text_tuple",
    "optional_text_converter",
    "text_converter",
    "text_tuple_converter",
    "tuple_converter",
]
