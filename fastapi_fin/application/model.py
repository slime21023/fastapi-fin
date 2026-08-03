"""Immutable application model produced from definitions."""

from dataclasses import dataclass

from .definitions import (
    ApplicationDefinition,
    GuardDefinition,
    InterceptorDefinition,
    LifecycleDefinition,
    ProviderDefinition,
    RouteDefinition,
    ServiceToken,
)


@dataclass(frozen=True, slots=True)
class ApplicationModel:
    """Validated application structure used by adapters and runtime."""

    routes: tuple[RouteDefinition, ...]
    providers: tuple[ProviderDefinition, ...]
    provider_order: tuple[ServiceToken, ...]
    guards: tuple[GuardDefinition, ...]
    interceptors: tuple[InterceptorDefinition, ...]
    lifecycle: LifecycleDefinition

    @classmethod
    def from_definition(
        cls,
        definition: ApplicationDefinition,
        provider_order: tuple[ServiceToken, ...],
    ) -> "ApplicationModel":
        return cls(
            routes=definition.routes,
            providers=definition.providers,
            provider_order=provider_order,
            guards=definition.guards,
            interceptors=definition.interceptors,
            lifecycle=definition.lifecycle,
        )

    def find_provider(self, token: ServiceToken) -> ProviderDefinition | None:
        """Return a provider by token."""
        return next((item for item in self.providers if item.token == token), None)


__all__ = ["ApplicationModel"]
