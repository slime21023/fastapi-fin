"""Framework-independent FastAPI-Fin core models and errors."""

from .cache import CachePolicy, CacheStore
from .config import ConfigSnapshot, SettingSpec
from .dependency import ContainerRuntime, ContainerSnapshot, ResolutionContext, ServiceBinding
from .errors import (
    DeclarationError,
    FastAPIFinError,
    RegistrationError,
    ResolutionError,
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
from .types import HttpMethod, Lifecycle, normalize_methods, normalize_path

__all__ = [
    "ApplicationStarted",
    "ApplicationStopping",
    "CachePolicy",
    "CacheStore",
    "ConfigSnapshot",
    "ContainerRuntime",
    "ContainerSnapshot",
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
    "Lifecycle",
    "MetadataSnapshot",
    "ModuleMetadata",
    "RegistrationError",
    "ResolutionContext",
    "ResolutionError",
    "RouteMetadata",
    "ServiceBinding",
    "SettingSpec",
    "Subscription",
    "SubscriptionSnapshot",
    "get_controller_metadata",
    "get_module_metadata",
    "get_route_metadata",
    "normalize_methods",
    "normalize_path",
]
