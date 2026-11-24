"""Immutable module declarations for contract-first composition."""

from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from itertools import chain, repeat
from types import MappingProxyType

from attrs import define, evolve, field
from dishka import DEFAULT_COMPONENT, Provider

from ._validation import normalize_contract, normalize_iterable, text_converter, tuple_converter
from .errors import AssemblyError, DefinitionError


def _normalize_contracts(values: Iterable[object]) -> tuple[object, ...]:
    contracts = normalize_iterable(values, "contracts")
    seen: set[object] = set()
    for contract in contracts:
        normalize_contract(contract)
        if contract in seen:
            raise DefinitionError(f"contract {contract!r} is listed more than once")
        seen.add(contract)
    return contracts


def _normalize_overrides(values: Mapping[object, object]) -> Mapping[object, object]:
    if not isinstance(values, Mapping):
        raise DefinitionError("overrides must be a mapping")
    for contract in values:
        normalize_contract(contract)
    return MappingProxyType(dict(values))


def _validate_provider(module_name: str, provider: object) -> None:
    if not isinstance(provider, Provider):
        raise DefinitionError("module providers must contain dishka Provider instances")
    if provider.component != DEFAULT_COMPONENT:
        raise DefinitionError(
            f"module {module_name!r} provider {provider!r} must not set a component; "
            "Module assigns it"
        )
    if provider.context_vars:
        raise DefinitionError(
            f"module {module_name!r} provider {provider!r} must not use from_context; "
            "declare context through build_container(context=...)"
        )


@define(frozen=True, slots=True)
class Module:
    """A named component with explicit public exports and imports."""

    name: str = field(converter=text_converter("module name"))
    providers: tuple[Provider, ...] = field(
        default=(), converter=tuple_converter("module providers")
    )
    exports: tuple[object, ...] = field(default=(), converter=_normalize_contracts)
    requires: tuple[object, ...] = field(default=(), converter=_normalize_contracts)

    def __attrs_post_init__(self) -> None:
        for provider in self.providers:
            _validate_provider(self.name, provider)
        exported = frozenset(self.exports)
        if conflict := next((item for item in self.requires if item in exported), None):
            raise DefinitionError(f"module {self.name!r} both exports and requires {conflict!r}")


def _index_exports(modules: tuple[Module, ...]) -> dict[object, str]:
    """Map every exported contract to its module, rejecting duplicate names and owners."""
    if not all(isinstance(module, Module) for module in modules):
        raise DefinitionError("application modules must contain Module values")
    name_counts = Counter(module.name for module in modules)
    if duplicate := next((name for name, count in name_counts.items() if count > 1), None):
        raise AssemblyError(f"duplicate module name: {duplicate!r}")
    owners: dict[object, str] = {}
    for contract, module_name in chain.from_iterable(map(_exports_of, modules)):
        if contract in owners:
            raise AssemblyError(
                f"contract {contract!r} is exported by modules "
                f"{owners[contract]!r} and {module_name!r}"
            )
        owners[contract] = module_name
    return owners


def _exports_of(module: Module) -> Iterator[tuple[object, str]]:
    return zip(module.exports, repeat(module.name), strict=False)


@define(frozen=True, slots=True)
class Application:
    """A collection of modules and optional test-owned contract instances."""

    modules: tuple[Module, ...] = field(
        default=(), converter=tuple_converter("application modules")
    )
    overrides: Mapping[object, object] = field(factory=dict, converter=_normalize_overrides)
    _exports: Mapping[object, str] = field(init=False, repr=False, eq=False)

    def __attrs_post_init__(self) -> None:
        owners = _index_exports(self.modules)
        if unknown := next((item for item in self.overrides if item not in owners), None):
            raise AssemblyError(f"override target {unknown!r} is not an exported contract")
        object.__setattr__(self, "_exports", MappingProxyType(owners))

    @property
    def exports(self) -> Mapping[object, str]:
        """Map each exported contract to its owning module."""
        return self._exports

    def with_overrides(self, overrides: Mapping[object, object]) -> "Application":
        """Return a new application with test-owned replacements, latest value winning."""
        return evolve(self, overrides={**self.overrides, **_normalize_overrides(overrides)})


__all__ = ["Application", "Module"]
