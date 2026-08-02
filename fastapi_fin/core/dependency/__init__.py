"""Framework-independent provider registration and runtime resolution."""

from ..types import Scope
from .providers import (
    Provider,
    ProviderRegistry,
    ServiceFactory,
    ServiceToken,
    normalize_scope,
)
from .runtime import ContainerRuntime, ResolutionContext

__all__ = [
    "ContainerRuntime",
    "Provider",
    "ProviderRegistry",
    "ResolutionContext",
    "Scope",
    "ServiceFactory",
    "ServiceToken",
    "normalize_scope",
]
