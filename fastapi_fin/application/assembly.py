"""Definition validation and application model assembly."""

from inspect import signature

from ..errors import AssemblyError
from ..features.guards import GuardDefinition
from ..features.interceptors import InterceptorDefinition
from .definitions import ApplicationDefinition, Inject, ProviderDefinition, ServiceToken
from .model import ApplicationModel


def assemble(definition: ApplicationDefinition) -> ApplicationModel:
    """Validate one definition and return its immutable application model."""
    if not isinstance(definition, ApplicationDefinition):
        raise AssemblyError("definition must be an ApplicationDefinition")

    _validate_route_conflicts(definition)
    providers = _validate_providers(definition)
    _validate_endpoint_injections(definition, providers)
    provider_order = _topological_provider_order(providers)
    return ApplicationModel.from_definition(definition, provider_order)


def _validate_route_conflicts(definition: ApplicationDefinition) -> None:
    seen: set[tuple[str, str]] = set()
    for route in definition.routes:
        for method in route.methods:
            key = (route.path, method.value)
            if key in seen:
                raise AssemblyError(f"duplicate route: {method.value} {route.path}")
            seen.add(key)


def _validate_providers(
    definition: ApplicationDefinition,
) -> dict[ServiceToken, ProviderDefinition]:
    providers: dict[ServiceToken, ProviderDefinition] = {}
    for provider in definition.providers:
        if provider.token in providers:
            raise AssemblyError(f"duplicate provider token: {provider.token!r}")
        providers[provider.token] = provider

    for provider in providers.values():
        for dependency in provider.dependencies:
            if dependency not in providers:
                raise AssemblyError(
                    f"provider {provider.token!r} depends on missing token {dependency!r}"
                )
            dependency_provider = providers[dependency]
            if (
                provider.scope.value == "application"
                and dependency_provider.scope.value == "request"
            ):
                raise AssemblyError(
                    f"application provider {provider.token!r} cannot depend on request provider "
                    f"{dependency!r}"
                )
    return providers


def _validate_endpoint_injections(
    definition: ApplicationDefinition,
    providers: dict[ServiceToken, ProviderDefinition],
) -> None:
    for route in definition.routes:
        try:
            parameters = signature(route.endpoint).parameters.values()
        except (TypeError, ValueError) as error:
            raise AssemblyError(f"cannot inspect route endpoint {route.endpoint!r}") from error
        for parameter in parameters:
            if isinstance(parameter.default, Inject) and parameter.default.token not in providers:
                raise AssemblyError(
                    f"route {route.path!r} injects missing token {parameter.default.token!r}"
                )
            if parameter.default is not parameter.empty and isinstance(
                parameter.default,
                (GuardDefinition, InterceptorDefinition),
            ):
                raise AssemblyError("policies must be attached to a route, not a parameter")


def _topological_provider_order(
    providers: dict[ServiceToken, ProviderDefinition],
) -> tuple[ServiceToken, ...]:
    visiting: set[ServiceToken] = set()
    visited: set[ServiceToken] = set()
    ordered: list[ServiceToken] = []

    def visit(token: ServiceToken) -> None:
        if token in visited:
            return
        if token in visiting:
            raise AssemblyError(f"circular provider dependency at {token!r}")
        visiting.add(token)
        for dependency in providers[token].dependencies:
            visit(dependency)
        visiting.remove(token)
        visited.add(token)
        ordered.append(token)

    for token in providers:
        visit(token)
    return tuple(ordered)


__all__ = ["assemble"]
