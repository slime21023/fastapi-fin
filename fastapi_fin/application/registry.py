"""Immutable application assembly registry."""

from collections.abc import Iterable

from attrs import evolve, field, frozen

from ..core.dependency import ProviderRegistry, Scope, ServiceFactory, ServiceToken
from ..core.errors import RegistrationError
from ..core.metadata import (
    ControllerMetadata,
    MetadataSnapshot,
    ModuleMetadata,
    get_controller_metadata,
    get_module_metadata,
)


def _validate_metadata(_instance: object, _attribute: object, value: object) -> None:
    if not isinstance(value, MetadataSnapshot):
        raise RegistrationError("application metadata must be a MetadataSnapshot instance")


def _validate_providers(_instance: object, _attribute: object, value: object) -> None:
    if not isinstance(value, ProviderRegistry):
        raise RegistrationError("application providers must be a ProviderRegistry instance")


def _normalize_controllers(
    controllers: Iterable[ControllerMetadata],
) -> tuple[ControllerMetadata, ...]:
    try:
        normalized = tuple(controllers)
    except TypeError as error:
        raise RegistrationError("controllers must be iterable") from error
    if not all(isinstance(controller, ControllerMetadata) for controller in normalized):
        raise RegistrationError("controllers must be ControllerMetadata instances")
    return normalized


@frozen(slots=True, kw_only=True)
class ApplicationRegistry:
    """Immutable application composition for routes and dependency providers.

    This is the high-level assembly API.  Metadata and provider declarations stay
    separate internally, while application code can compose both from one value.
    """

    metadata: MetadataSnapshot = field(
        factory=MetadataSnapshot,
        validator=_validate_metadata,
    )
    providers: ProviderRegistry = field(
        factory=ProviderRegistry,
        validator=_validate_providers,
    )

    def controller(
        self,
        controller: ControllerMetadata | type[object],
    ) -> "ApplicationRegistry":
        """Return a new registry containing one decorated controller."""
        metadata = (
            controller
            if isinstance(controller, ControllerMetadata)
            else get_controller_metadata(controller)
        )
        return evolve(self, metadata=self.metadata.register(metadata))

    def module(
        self,
        module: ModuleMetadata | type[object],
    ) -> "ApplicationRegistry":
        """Return a new registry containing a module's flattened controllers."""
        metadata = module if isinstance(module, ModuleMetadata) else get_module_metadata(module)
        registry = self
        for controller in _normalize_controllers(metadata.flatten_controllers()):
            registry = registry.controller(controller)
        return registry

    def provide(
        self,
        token: ServiceToken,
        factory: ServiceFactory | None = None,
        *,
        scope: str | Scope = Scope.TRANSIENT,
        lazy: bool = True,
    ) -> "ApplicationRegistry":
        """Return a new registry containing one dependency provider."""
        return evolve(
            self,
            providers=self.providers.provide(
                token,
                factory,
                scope=scope,
                lazy=lazy,
            ),
        )


__all__ = ["ApplicationRegistry"]
