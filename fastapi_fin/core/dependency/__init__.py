"""Framework-independent dependency binding and runtime resolution."""

from .container import (
    ContainerRuntime,
    ContainerSnapshot,
    ResolutionContext,
    ServiceBinding,
    ServiceFactory,
    ServiceToken,
    normalize_lifecycle,
)

__all__ = [
    "ContainerRuntime",
    "ContainerSnapshot",
    "ResolutionContext",
    "ServiceBinding",
    "ServiceFactory",
    "ServiceToken",
    "normalize_lifecycle",
]
