"""Compose and own Dishka containers without a web framework.

Each module's providers live in their own Dishka component, so a provider cannot reach
another module's internals. Components are connected only by alias "bridges": exported
contracts are aliased into the default component, and required contracts are aliased from
the default component into the requiring module.
"""

from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from itertools import chain
from types import MappingProxyType
from typing import cast

from dishka import (
    DEFAULT_COMPONENT,
    STRICT_VALIDATION,
    AsyncContainer,
    BaseScope,
    Provider,
    Scope,
    make_async_container,
)
from dishka.exceptions import AliasedFactoryNotFoundError, InvalidGraphError
from dishka.provider import BaseProvider

from ._validation import Contract, ModuleName, normalize_contract
from .errors import AssemblyError, DefinitionError
from .modules import FinProxy, Module

_EMPTY_CONTEXT: Mapping[Contract, BaseScope] = MappingProxyType({})


def build_container(
    fin: FinProxy, *, context: Mapping[Contract, BaseScope] = _EMPTY_CONTEXT
) -> AsyncContainer:
    """Validate and build a container; the caller owns its shutdown.

    The default component exposes exports and context. Supply declared context values
    when entering their scopes. Overrides are externally owned APP-scoped instances.
    """
    if not isinstance(fin, FinProxy):
        raise AssemblyError("build_container requires a FinProxy")
    if not isinstance(context, Mapping):
        raise DefinitionError("context must be a mapping of contracts to dishka scopes")

    context_provider = _context_provider(context, fin.exports)
    providers = [
        *_module_providers(fin),
        _export_bridge(fin.exports),
        *_import_bridges(fin, context),
        context_provider,
        *_override_providers(fin),
    ]
    try:
        return make_async_container(*providers, validation_settings=STRICT_VALIDATION)
    except (InvalidGraphError, AliasedFactoryNotFoundError) as error:
        raise AssemblyError(f"dependency graph is invalid: {error}") from error


@asynccontextmanager
async def open_container(
    fin: FinProxy, *, context: Mapping[Contract, BaseScope] = _EMPTY_CONTEXT
) -> AsyncIterator[AsyncContainer]:
    """Build a container and close it when the caller exits."""
    container = build_container(fin, context=context)
    try:
        yield container
    finally:
        await container.close()


def _module_providers(fin: FinProxy) -> list[BaseProvider]:
    return list(chain.from_iterable(map(_component_providers, fin.modules)))


def _component_providers(module: Module) -> list[BaseProvider]:
    return [provider.to_component(module.name) for provider in module.providers]


def _export_bridge(exports: Mapping[Contract, ModuleName]) -> Provider:
    """Expose each exported contract in the default component."""
    bridge = Provider()
    for contract, owner in exports.items():
        bridge.alias(_as_type(contract), component=owner)
    return bridge


def _import_bridges(fin: FinProxy, context: Mapping[Contract, BaseScope]) -> list[Provider]:
    """Let each module see the contracts it requires from the default component."""
    return [
        _import_bridge(module, fin.exports, context) for module in fin.modules if module.requires
    ]


def _import_bridge(
    module: Module, exports: Mapping[Contract, ModuleName], context: Mapping[Contract, BaseScope]
) -> Provider:
    bridge = Provider(component=module.name)
    for contract in module.requires:
        if contract not in exports and contract not in context:
            raise AssemblyError(
                f"module {module.name!r} requires {contract!r}, "
                "which is neither exported by a module nor provided as context"
            )
        bridge.alias(_as_type(contract), component=DEFAULT_COMPONENT)
    return bridge


def _context_provider(
    context: Mapping[Contract, BaseScope], exports: Mapping[Contract, ModuleName]
) -> Provider:
    provider = Provider()
    for contract, scope in context.items():
        normalize_contract(contract)
        if not isinstance(scope, BaseScope):
            raise DefinitionError("context scopes must be dishka scopes")
        if contract in exports:
            raise AssemblyError(
                f"context type {contract!r} is also exported by module {exports[contract]!r}"
            )
        provider.from_context(provides=contract, scope=scope)
    return provider


def _override_providers(fin: FinProxy) -> list[Provider]:
    """Replace overridden contracts for both external callers and their owning module."""
    if not fin.overrides:
        return []
    replacements = Provider(scope=Scope.APP)
    owner_bridges = []
    for contract, instance in fin.overrides.items():
        replacements.provide(_constant(instance), provides=contract, override=True)
        owner_bridge = Provider(component=fin.exports[contract])
        owner_bridge.alias(_as_type(contract), component=DEFAULT_COMPONENT, override=True)
        owner_bridges.append(owner_bridge)
    return [replacements, *owner_bridges]


def _constant(value: object) -> Callable[[], object]:
    def factory() -> object:
        return value

    return factory


def _as_type(contract: Contract) -> type:
    """Dishka's stubs demand ``type``; contracts may be any hashable type hint."""
    return cast("type", contract)


__all__ = ["build_container", "open_container"]
