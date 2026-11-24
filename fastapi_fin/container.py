"""Compose and own Dishka containers without a web framework."""

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

from .errors import AssemblyError, DefinitionError
from .modules import Application, _normalize_contract

_EMPTY_CONTEXT: Mapping[object, BaseScope] = MappingProxyType({})


def _value_factory(value: object) -> Callable[[], object]:
    def factory() -> object:
        return value

    return factory


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
    exports = application.exports
    host = _context_provider(context, exports)

    export_bridge = Provider()
    for contract, owner in exports.items():
        export_bridge.alias(cast("type", contract), component=owner)

    import_bridges = []
    for module in application.modules:
        if not module.requires:
            continue
        bridge = Provider(component=module.name)
        for contract in module.requires:
            if contract not in exports and contract not in context:
                raise AssemblyError(
                    f"module {module.name!r} requires {contract!r}, "
                    "which is neither exported by a module nor provided as context"
                )
            bridge.alias(cast("type", contract), component=DEFAULT_COMPONENT)
        import_bridges.append(bridge)

    replacements = Provider(scope=Scope.APP)
    replacement_bridges = []
    for contract, value in application.overrides.items():
        replacements.provide(_value_factory(value), provides=contract, override=True)
        bridge = Provider(component=exports[contract])
        bridge.alias(cast("type", contract), component=DEFAULT_COMPONENT, override=True)
        replacement_bridges.append(bridge)

    try:
        return make_async_container(
            *(
                provider.to_component(module.name)
                for module in application.modules
                for provider in module.providers
            ),
            export_bridge,
            *import_bridges,
            host,
            replacements,
            *replacement_bridges,
            validation_settings=STRICT_VALIDATION,
        )
    except (InvalidGraphError, AliasedFactoryNotFoundError) as error:
        raise AssemblyError(f"dependency graph is invalid: {error}") from error


def _context_provider(
    context: Mapping[object, BaseScope], exports: Mapping[object, str]
) -> Provider:
    provider = Provider()
    for contract, scope in context.items():
        _normalize_contract(contract)
        if not isinstance(scope, BaseScope):
            raise DefinitionError("context scopes must be dishka scopes")
        if contract in exports:
            raise AssemblyError(
                f"context type {contract!r} is also exported by module {exports[contract]!r}"
            )
        provider.from_context(provides=contract, scope=scope)
    return provider


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


__all__ = ["build_container", "open_container"]
