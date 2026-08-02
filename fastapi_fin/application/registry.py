"""Immutable metadata registry used during application assembly."""

from collections.abc import Iterable

from attrs import evolve, field, frozen

from ..core.errors import RegistrationError
from ..core.metadata import (
    ControllerMetadata,
    MetadataSnapshot,
    ModuleMetadata,
    get_controller_metadata,
    get_module_metadata,
)


def _validate_snapshot(_instance: object, _attribute: object, snapshot: object) -> None:
    if not isinstance(snapshot, MetadataSnapshot):
        raise RegistrationError("registry snapshot must be a MetadataSnapshot instance")


def _normalize_controllers(
    controllers: Iterable[ControllerMetadata],
) -> tuple[ControllerMetadata, ...]:
    try:
        return tuple(controllers)
    except TypeError as error:
        raise RegistrationError("controllers must be iterable") from error


@frozen(slots=True, kw_only=True)
class MetadataRegistry:
    """Persistent registry whose writes return a new registry instance."""

    snapshot: MetadataSnapshot = field(
        factory=MetadataSnapshot,
        validator=_validate_snapshot,
    )

    def register(self, controller: ControllerMetadata) -> "MetadataRegistry":
        """Return a registry containing one additional controller."""
        if not isinstance(controller, ControllerMetadata):
            raise RegistrationError("controller must be a ControllerMetadata instance")
        return evolve(self, snapshot=self.snapshot.register(controller))

    def register_controller(self, controller: type[object]) -> "MetadataRegistry":
        """Return a registry containing a decorated controller class."""
        return self.register(get_controller_metadata(controller))

    def register_many(
        self,
        controllers: Iterable[ControllerMetadata],
    ) -> "MetadataRegistry":
        """Return a registry containing all controllers in order."""
        registry = self
        for controller in _normalize_controllers(controllers):
            registry = registry.register(controller)
        return registry

    def register_module(
        self,
        module: ModuleMetadata | type[object],
    ) -> "MetadataRegistry":
        """Return a registry containing a module's flattened controllers."""
        metadata = module if isinstance(module, ModuleMetadata) else get_module_metadata(module)
        return self.register_many(metadata.flatten_controllers())
