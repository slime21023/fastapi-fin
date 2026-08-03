"""FastAPI-Fin 1.0.0: explicit application definitions for FastAPI."""

from importlib import import_module
from typing import TYPE_CHECKING

from .application import (
    ApplicationDefinition,
    Endpoint,
    HttpMethod,
    Inject,
    LifecycleDefinition,
    ProviderDefinition,
    ProviderFactory,
    RouteDefinition,
    Scope,
    ServiceToken,
    assemble,
    inject,
    provide,
    route,
)
from .errors import (
    AccessDeniedError,
    AdapterError,
    AssemblyError,
    DefinitionError,
    FastAPIFinError,
    ResolutionError,
    RuntimeClosedError,
)
from .features import (
    CachePolicy,
    CacheStore,
    Configuration,
    EventBus,
    EventHandler,
    EventSubscription,
    GuardDefinition,
    GuardPredicate,
    InterceptorDefinition,
    InterceptorHandler,
    SettingDefinition,
    enforce_guards,
    execute_interceptors,
    guard,
    interceptor,
)
from .runtime import ApplicationRuntime, RequestContext

if TYPE_CHECKING:
    from .adapters import FastAPIAdapter, Lifespan

__version__ = "1.0.0"


def __getattr__(name: str) -> object:
    """Load FastAPI-dependent exports only when requested."""
    if name in {"FastAPIAdapter", "Lifespan"}:
        module = import_module(".adapters", __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AccessDeniedError",
    "AdapterError",
    "ApplicationDefinition",
    "ApplicationRuntime",
    "AssemblyError",
    "CachePolicy",
    "CacheStore",
    "Configuration",
    "DefinitionError",
    "Endpoint",
    "EventBus",
    "EventHandler",
    "EventSubscription",
    "FastAPIAdapter",
    "FastAPIFinError",
    "GuardDefinition",
    "GuardPredicate",
    "HttpMethod",
    "Inject",
    "InterceptorDefinition",
    "InterceptorHandler",
    "LifecycleDefinition",
    "Lifespan",
    "ProviderDefinition",
    "ProviderFactory",
    "RequestContext",
    "ResolutionError",
    "RouteDefinition",
    "RuntimeClosedError",
    "Scope",
    "ServiceToken",
    "SettingDefinition",
    "__version__",
    "assemble",
    "enforce_guards",
    "execute_interceptors",
    "guard",
    "inject",
    "interceptor",
    "provide",
    "route",
]
