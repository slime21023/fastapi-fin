"""FastAPI-Fin: engineering architecture extensions for FastAPI."""

from importlib import import_module
from typing import TYPE_CHECKING

from .application import (
    CompiledApplication,
    CompiledRoute,
    MetadataRegistry,
    compile_application,
    connect,
    controller,
    delete,
    get,
    guard,
    head,
    module,
    options,
    patch,
    post,
    put,
    route,
    trace,
    use_interceptor,
)
from .core import (
    ApplicationStarted,
    ApplicationStopping,
    CachePolicy,
    CacheStore,
    ConfigSnapshot,
    ContainerRuntime,
    ContainerSnapshot,
    ControllerMetadata,
    DeclarationError,
    ErrorHandler,
    EventDescriptor,
    EventDispatcher,
    EventSubscription,
    FastAPIFinError,
    GuardPolicy,
    GuardRule,
    HttpMethod,
    InterceptorChain,
    InterceptorSpec,
    Lifecycle,
    MetadataSnapshot,
    ModuleMetadata,
    RegistrationError,
    ResolutionContext,
    ResolutionError,
    RouteMetadata,
    ServiceBinding,
    SettingSpec,
    Subscription,
    SubscriptionSnapshot,
    get_controller_metadata,
    get_module_metadata,
    get_route_metadata,
)

if TYPE_CHECKING:
    from .adapters import AdapterError, FastAPIAdapter, container_dependency

__version__ = "0.1.0"


def __getattr__(name: str) -> object:
    """Load FastAPI-dependent exports only when they are requested."""
    if name in {"AdapterError", "FastAPIAdapter", "container_dependency"}:
        adapter_module = import_module(".adapters", __name__)
        value = getattr(adapter_module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AdapterError",
    "ApplicationStarted",
    "ApplicationStopping",
    "CachePolicy",
    "CacheStore",
    "CompiledApplication",
    "CompiledRoute",
    "ConfigSnapshot",
    "ContainerRuntime",
    "ContainerSnapshot",
    "ControllerMetadata",
    "DeclarationError",
    "ErrorHandler",
    "EventDescriptor",
    "EventDispatcher",
    "EventSubscription",
    "FastAPIAdapter",
    "FastAPIFinError",
    "GuardPolicy",
    "GuardRule",
    "HttpMethod",
    "InterceptorChain",
    "InterceptorSpec",
    "Lifecycle",
    "MetadataRegistry",
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
    "__version__",
    "compile_application",
    "connect",
    "container_dependency",
    "controller",
    "delete",
    "get",
    "get_controller_metadata",
    "get_module_metadata",
    "get_route_metadata",
    "guard",
    "head",
    "module",
    "options",
    "patch",
    "post",
    "put",
    "route",
    "trace",
    "use_interceptor",
]
