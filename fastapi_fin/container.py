"""Compose and own Dishka containers without a web framework.

Each module's providers live in their own Dishka component, so a provider cannot reach
another module's internals. Components are connected only by alias "bridges": exported
contracts are aliased into the default component, and required contracts are aliased from
the default component into the requiring module.
"""

from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
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

from ._validation import normalize_contract
from .errors import AssemblyError, DefinitionError
from .modules import Application, Module

_EMPTY_CONTEXT: Mapping[object, BaseScope] = MappingProxyType({})


def build_container(
    application: Application, *, context: Mapping[object, BaseScope] = _EMPTY_CONTEXT
) -> AsyncContainer:
    """Validate and build a container; the caller owns its shutdown.

    The default component exposes exports and context. Supply declared context values
    when entering their scopes. Overrides are externally owned APP-scoped instances.
    """
    if not isinstance(application, Application):
        raise AssemblyError("build_container requires an Application")
    if not isinstance(context, Mapping):
        raise DefinitionError("context must be a mapping of contracts to dishka scopes")

    context_provider = _context_provider(context, application.exports)
    providers = [
        *_module_providers(application),
        _export_bridge(application.exports),
        *_import_bridges(application, context),
        context_provider,
        *_override_providers(application),
    ]
    try:
        return make_async_container(*providers, validation_settings=STRICT_VALIDATION)
    except (InvalidGraphError, AliasedFactoryNotFoundError) as error:
        raise AssemblyError(f"dependency graph is invalid: {error}") from error


@asynccontextmanager
async def open_container(
    application: Application, *, context: Mapping[object, BaseScope] = _EMPTY_CONTEXT
) -> AsyncIterator[AsyncContainer]:
    """Build a container and close it when the caller exits."""
    container = build_container(application, context=context)
    try:
        yield container
    finally:
        await container.close()


def _module_providers(application: Application) -> list[BaseProvider]:
    return [
        provider.to_component(module.name)
        for module in application.modules
        for provider in module.providers
    ]


def _export_bridge(exports: Mapping[object, str]) -> Provider:
    """Expose each exported contract in the default component."""
    bridge = Provider()
    for contract, owner in exports.items():
        bridge.alias(_as_type(contract), component=owner)
    return bridge


def _import_bridges(
    application: Application, context: Mapping[object, BaseScope]
) -> list[Provider]:
    """Let each module see the contracts it requires from the default component."""
    return [
        _import_bridge(module, application.exports, context)
        for module in application.modules
        if module.requires
    ]


def _import_bridge(
    module: Module, exports: Mapping[object, str], context: Mapping[object, BaseScope]
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
    context: Mapping[object, BaseScope], exports: Mapping[object, str]
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


def _override_providers(application: Application) -> list[Provider]:
    """Replace overridden contracts for both external callers and their owning module."""
    if not application.overrides:
        return []
    replacements = Provider(scope=Scope.APP)
    owner_bridges = []
    for contract, instance in application.overrides.items():
        replacements.provide(_constant(instance), provides=contract, override=True)
        owner_bridge = Provider(component=application.exports[contract])
        owner_bridge.alias(_as_type(contract), component=DEFAULT_COMPONENT, override=True)
        owner_bridges.append(owner_bridge)
    return [replacements, *owner_bridges]


def _constant(value: object) -> Callable[[], object]:
    def factory() -> object:
        return value

    return factory


def _as_type(contract: object) -> type:
    """Dishka's stubs demand ``type``; contracts may be any hashable type hint."""
    return cast("type", contract)


__all__ = ["build_container", "open_container"]
