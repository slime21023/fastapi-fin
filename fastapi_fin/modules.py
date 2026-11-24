"""Immutable module declarations for contract-first composition."""

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from attrs import define, evolve, field
from dishka import DEFAULT_COMPONENT, Provider

from ._validation import normalize_iterable
from .errors import AssemblyError, DefinitionError


def _normalize_contract(value: object) -> object:
    if isinstance(value, str) or value is None:
        raise DefinitionError("contracts must be type hints, not strings or None")
    try:
        hash(value)
    except TypeError as error:
        raise DefinitionError("contracts must be hashable type hints") from error
    return value


def _normalize_contracts(values: Iterable[object]) -> tuple[object, ...]:
    contracts = normalize_iterable(values, "contracts")
    seen: set[object] = set()
    for value in contracts:
        _normalize_contract(value)
        if value in seen:
            raise DefinitionError(f"contract {value!r} is listed more than once")
        seen.add(value)
    return contracts


def _normalize_name(value: str) -> str:
    if not isinstance(value, str) or not (value := value.strip()):
        raise DefinitionError("module name must be non-empty text")
    return value


def _normalize_overrides(values: Mapping[object, object]) -> Mapping[object, object]:
    if not isinstance(values, Mapping):
        raise DefinitionError("overrides must be a mapping")
    for contract in values:
        _normalize_contract(contract)
    return MappingProxyType(dict(values))


@define(frozen=True, slots=True)
class Module:
    """A named component with explicit public exports and imports."""

    name: str = field(converter=_normalize_name)
    providers: tuple[Provider, ...] = field(
        default=(), converter=lambda values: normalize_iterable(values, "module providers")
    )
    exports: tuple[object, ...] = field(default=(), converter=_normalize_contracts)
    requires: tuple[object, ...] = field(default=(), converter=_normalize_contracts)

    def __attrs_post_init__(self) -> None:
        for provider in self.providers:
            if not isinstance(provider, Provider):
                raise DefinitionError("module providers must contain dishka Provider instances")
            if provider.component != DEFAULT_COMPONENT:
                raise DefinitionError(
                    f"module {self.name!r} provider {provider!r} must not set a component; Module assigns it"
                )
            if provider.context_vars:
                raise DefinitionError(
                    f"module {self.name!r} provider {provider!r} must not use from_context; "
                    "declare context through build_container(context=...)"
                )
        for contract in self.requires:
            if contract in self.exports:
                raise DefinitionError(
                    f"module {self.name!r} both exports and requires {contract!r}"
                )


@define(frozen=True, slots=True)
class Application:
    """A collection of modules and optional test-owned contract instances."""

    modules: tuple[Module, ...] = field(
        default=(), converter=lambda values: normalize_iterable(values, "application modules")
    )
    overrides: Mapping[object, object] = field(factory=dict, converter=_normalize_overrides)
    _exports: Mapping[object, str] = field(init=False, repr=False, eq=False)

    def __attrs_post_init__(self) -> None:
        names: set[str] = set()
        exports: dict[object, str] = {}
        for module in self.modules:
            if not isinstance(module, Module):
                raise DefinitionError("application modules must contain Module values")
            if module.name in names:
                raise AssemblyError(f"duplicate module name: {module.name!r}")
            names.add(module.name)
            for contract in module.exports:
                if contract in exports:
                    raise AssemblyError(
                        f"contract {contract!r} is exported by modules "
                        f"{exports[contract]!r} and {module.name!r}"
                    )
                exports[contract] = module.name
        for contract in self.overrides:
            if contract not in exports:
                raise AssemblyError(f"override target {contract!r} is not an exported contract")
        object.__setattr__(self, "_exports", MappingProxyType(exports))

    @property
    def exports(self) -> Mapping[object, str]:
        """Map each exported contract to its owning module."""
        return self._exports

    def with_overrides(self, overrides: Mapping[object, object]) -> "Application":
        """Return a new application with test-owned replacements, latest value winning."""
        return evolve(self, overrides={**self.overrides, **_normalize_overrides(overrides)})


__all__ = ["Application", "Module"]
