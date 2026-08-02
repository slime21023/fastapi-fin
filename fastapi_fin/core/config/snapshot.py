"""Typed configuration snapshots independent from environment or HTTP."""

from collections.abc import Callable, Iterable, Mapping
from typing import Final, TypeVar

from attrs import evolve, field, frozen, validators

from ..errors import DeclarationError, RegistrationError, ResolutionError
from ..types import _validate_nonnegative_integer

SettingParser = Callable[..., object]
ConfigValueT = TypeVar("ConfigValueT")
_MISSING_DEFAULT: Final = object()


def _identity(value: object) -> object:
    return value


def _normalize_name(name: str) -> str:
    if not isinstance(name, str):
        raise DeclarationError("setting name must be a string")
    normalized = name.strip()
    if not normalized:
        raise DeclarationError("setting name must not be empty")
    return normalized


def _validate_parser(parser: SettingParser) -> SettingParser:
    if not callable(parser):
        raise DeclarationError("setting parser must be callable")
    return parser


def _normalize_values(
    values: Iterable[tuple[str, object]],
) -> tuple[tuple[str, object], ...]:
    normalized: list[tuple[str, object]] = []
    names: set[str] = set()
    for name, value in values:
        normalized_name = _normalize_name(name)
        if normalized_name in names:
            raise RegistrationError(f"configuration setting is duplicated: {normalized_name!r}")
        names.add(normalized_name)
        normalized.append((normalized_name, value))
    return tuple(normalized)


def _normalize_sensitive_names(names: Iterable[str]) -> frozenset[str]:
    return frozenset(_normalize_name(name) for name in names)


@frozen(slots=True, kw_only=True)
class SettingSpec:
    """Immutable description of one configuration setting."""

    name: str = field(converter=_normalize_name)
    parser: SettingParser = field(default=_identity, converter=_validate_parser)
    required: bool = field(default=True, validator=validators.instance_of(bool))
    sensitive: bool = field(default=False, validator=validators.instance_of(bool))
    default: object = field(default=_MISSING_DEFAULT, repr=False)

    def __attrs_post_init__(self) -> None:
        if self.required and self.default is not _MISSING_DEFAULT:
            raise DeclarationError("required configuration settings cannot define a default")

    @property
    def has_default(self) -> bool:
        """Whether the setting supplies a fallback value when raw input is absent."""
        return self.default is not _MISSING_DEFAULT


def _parse_setting(spec: SettingSpec, raw_value: object) -> object:
    try:
        return spec.parser(raw_value)
    except Exception as error:
        raise DeclarationError(f"invalid configuration setting: {spec.name!r}") from error


def _normalize_specs(specs: Iterable[SettingSpec]) -> tuple[SettingSpec, ...]:
    normalized = tuple(specs)
    if not all(isinstance(spec, SettingSpec) for spec in normalized):
        raise DeclarationError("configuration specs must be SettingSpec instances")
    if len({spec.name for spec in normalized}) != len(normalized):
        raise RegistrationError("configuration setting specs must have unique names")
    return normalized


@frozen(slots=True, kw_only=True)
class ConfigSnapshot:
    """Immutable typed configuration values."""

    values: tuple[tuple[str, object], ...] = field(
        factory=tuple,
        converter=_normalize_values,
    )
    sensitive_names: frozenset[str] = field(
        factory=frozenset,
        converter=_normalize_sensitive_names,
    )
    specs: tuple[SettingSpec, ...] = field(
        factory=tuple,
        converter=_normalize_specs,
    )
    version: int = field(default=0, validator=_validate_nonnegative_integer)

    def __attrs_post_init__(self) -> None:
        """Derive sensitive names from the immutable setting specifications."""
        declared_sensitive_names = frozenset(spec.name for spec in self.specs if spec.sensitive)
        object.__setattr__(
            self,
            "sensitive_names",
            self.sensitive_names | declared_sensitive_names,
        )

    def __repr__(self) -> str:
        """Render diagnostics without exposing sensitive configuration values."""
        return (
            f"{type(self).__name__}(values={self.redacted()!r}, "
            f"sensitive_names={self.sensitive_names!r}, specs={self.specs!r}, "
            f"version={self.version!r})"
        )

    @classmethod
    def load(
        cls,
        raw: Mapping[str, object],
        specs: Iterable[SettingSpec],
    ) -> "ConfigSnapshot":
        """Parse raw values and return a normalized configuration snapshot."""
        if not isinstance(raw, Mapping):
            raise DeclarationError("raw configuration must be a mapping")
        specs = _normalize_specs(specs)
        spec_names = {spec.name for spec in specs}
        unknown_names = set(raw) - spec_names
        if unknown_names:
            raise DeclarationError(f"unknown configuration settings: {sorted(unknown_names)!r}")

        values: list[tuple[str, object]] = []
        sensitive_names: set[str] = set()
        for spec in specs:
            if spec.name not in raw:
                if spec.required:
                    raise DeclarationError(f"missing configuration setting: {spec.name!r}")
                if not spec.has_default:
                    continue
                raw_value = spec.default
            else:
                raw_value = raw[spec.name]
            value = _parse_setting(spec, raw_value)
            values.append((spec.name, value))
            if spec.sensitive:
                sensitive_names.add(spec.name)

        return cls(
            values=tuple(values),
            sensitive_names=frozenset(sensitive_names),
            specs=specs,
        )

    def get(self, name: str) -> object:
        """Retrieve one already-parsed setting."""
        normalized_name = _normalize_name(name)
        for key, value in self.values:
            if key == normalized_name:
                return value
        raise ResolutionError(f"configuration setting is not loaded: {normalized_name!r}")

    def get_typed(self, name: str, expected_type: type[ConfigValueT]) -> ConfigValueT:
        """Retrieve a setting and verify its runtime type at the boundary."""
        if not isinstance(expected_type, type):
            raise DeclarationError("expected_type must be a class")
        value = self.get(name)
        if not isinstance(value, expected_type):
            raise ResolutionError(f"configuration setting {name!r} is not {expected_type.__name__}")
        return value

    def replace(self, name: str, value: object) -> "ConfigSnapshot":
        """Return a new snapshot with one setting replaced."""
        normalized_name = _normalize_name(name)
        if normalized_name not in {key for key, _value in self.values}:
            raise ResolutionError(f"configuration setting is not loaded: {normalized_name!r}")
        spec = next((item for item in self.specs if item.name == normalized_name), None)
        replacement = value
        if spec is not None:
            replacement = _parse_setting(spec, value)
        updated = tuple(
            (key, replacement if key == normalized_name else current)
            for key, current in self.values
        )
        return evolve(self, values=updated, version=self.version + 1)

    def redacted(self) -> tuple[tuple[str, object], ...]:
        """Return values safe for diagnostic logging."""
        return tuple(
            (name, "<redacted>" if name in self.sensitive_names else value)
            for name, value in self.values
        )
