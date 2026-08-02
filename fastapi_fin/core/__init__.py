"""Framework-independent FastAPI-Fin core models and errors."""

from .cache import CachePolicy, CacheStore
from .config import ConfigSnapshot, SettingSpec
from .dependency import (
    ContainerRuntime,
    Provider,
    ProviderRegistry,
    ResolutionContext,
    Scope,
)
from .errors import (
    DeclarationError,
    FastAPIFinError,
    RegistrationError,
    ResolutionError,
    RuntimeClosedError,
)
from .events import (
    ApplicationStarted,
    ApplicationStopping,
    EventDescriptor,
    EventDispatcher,
    EventSubscription,
    Subscription,
    SubscriptionSnapshot,
)
from .guard import GuardPolicy, GuardRule
from .interceptor import ErrorHandler, InterceptorChain, InterceptorSpec
from .metadata import (
    ControllerMetadata,
    MetadataSnapshot,
    ModuleMetadata,
    RouteMetadata,
    get_controller_metadata,
    get_module_metadata,
    get_route_metadata,
)
from .types import HttpMethod, normalize_methods, normalize_path

__all__ = [
    "ApplicationStarted",
    "ApplicationStopping",
    "CachePolicy",
    "CacheStore",
    "ConfigSnapshot",
    "ContainerRuntime",
    "ControllerMetadata",
    "DeclarationError",
    "ErrorHandler",
    "EventDescriptor",
    "EventDispatcher",
    "EventSubscription",
    "FastAPIFinError",
    "GuardPolicy",
    "GuardRule",
    "HttpMethod",
    "InterceptorChain",
    "InterceptorSpec",
    "MetadataSnapshot",
    "ModuleMetadata",
    "Provider",
    "ProviderRegistry",
    "RegistrationError",
    "ResolutionContext",
    "ResolutionError",
    "RouteMetadata",
    "RuntimeClosedError",
    "Scope",
    "SettingSpec",
    "Subscription",
    "SubscriptionSnapshot",
    "get_controller_metadata",
    "get_module_metadata",
    "get_route_metadata",
    "normalize_methods",
    "normalize_path",
]
