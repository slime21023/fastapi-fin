"""Optional immutable configuration values."""

from collections.abc import Mapping
from typing import Any

from attrs import define, field

from .._validation import (
    callable_validator,
    immutable_mapping,
)
from ..errors import DefinitionError

_MISSING = object()


def _validate_name(_instance: object, _attribute: object, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DefinitionError("setting name must not be empty")


def _validate_flags(_instance: object, _attribute: object, value: object) -> None:
    if not isinstance(value, bool):
        raise DefinitionError("setting flags must be bool")


@define(frozen=True, slots=True)
class SettingDefinition:
    name: str = field(validator=_validate_name)
    parser: Any = field(validator=callable_validator("setting parser"))
    required: bool = field(default=True, validator=_validate_flags)
    default: object = _MISSING
    sensitive: bool = field(default=False, validator=_validate_flags)

    def __attrs_post_init__(self) -> None:
        if self.required and self.default is not _MISSING:
            raise DefinitionError("required setting cannot define a default")


@define(frozen=True, slots=True)
class Configuration:
    """Parsed immutable settings with redacted representation for secrets."""

    values: Mapping[str, object] = field(
        factory=dict,
        converter=lambda value: immutable_mapping(value, "configuration values"),
    )
    sensitive_names: frozenset[str] = field(
        factory=frozenset,
        converter=frozenset,
    )

    @classmethod
    def load(
        cls,
        raw: Mapping[str, object],
        settings: tuple[SettingDefinition, ...],
    ) -> "Configuration":
        if not isinstance(raw, Mapping):
            raise DefinitionError("configuration input must be a mapping")
        try:
            normalized_settings = tuple(settings)
        except TypeError as error:
            raise DefinitionError("configuration settings must be iterable") from error
        if not all(isinstance(item, SettingDefinition) for item in normalized_settings):
            raise DefinitionError("configuration settings contain invalid values")
        names = [item.name for item in normalized_settings]
        if len(names) != len(set(names)):
            raise DefinitionError("configuration setting names must be unique")
        if not all(isinstance(name, str) for name in raw):
            raise DefinitionError("configuration setting names must be strings")
        parsed: dict[str, object] = {}
        sensitive: set[str] = set()
        known = set(names)
        unknown = set(raw) - known
        if unknown:
            raise DefinitionError(f"unknown configuration settings: {sorted(unknown)!r}")
        for setting in normalized_settings:
            if setting.name in raw:
                value = raw[setting.name]
            elif setting.default is not _MISSING:
                value = setting.default
            elif setting.required:
                raise DefinitionError(f"missing configuration setting: {setting.name!r}")
            else:
                continue
            try:
                parsed[setting.name] = setting.parser(value)
            except Exception as error:
                raise DefinitionError(f"invalid configuration setting: {setting.name!r}") from error
            if setting.sensitive:
                sensitive.add(setting.name)
        return cls(values=parsed, sensitive_names=sensitive)

    def get(self, name: str) -> object:
        try:
            return self.values[name]
        except KeyError as error:
            raise DefinitionError(f"unknown configuration setting: {name!r}") from error

    def redacted(self) -> dict[str, object]:
        return {
            name: "<redacted>" if name in self.sensitive_names else value
            for name, value in self.values.items()
        }

    def __repr__(self) -> str:
        return f"Configuration(values={self.redacted()!r})"


__all__ = ["Configuration", "SettingDefinition"]
