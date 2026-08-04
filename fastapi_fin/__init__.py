"""FastAPI-Fin 1.0.1: explicit application definitions for FastAPI."""

from importlib import import_module
from typing import TYPE_CHECKING

from .application import (
    ApplicationDefinition,
    ApplicationRouter,
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
from .security import (
    AuthenticatedPrincipal,
    AuthenticationError,
    AuthorizationError,
    InsufficientScopeError,
    InvalidTokenError,
    JwtIssuer,
    JwtKeyResolver,
    JwtKeySet,
    JwtVerifier,
    MissingCredentialsError,
    PrincipalPolicy,
    SecurityDependencyError,
    SecurityError,
    require_roles,
    require_scopes,
)

if TYPE_CHECKING:
    from .adapters import Authenticator, FastAPIAdapter, FastAPISecurity, Lifespan

__version__ = "1.0.1"


def __getattr__(name: str) -> object:
    """Load FastAPI-dependent exports only when requested."""
    if name in {"Authenticator", "FastAPIAdapter", "FastAPISecurity", "Lifespan"}:
        module = import_module(".adapters", __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AccessDeniedError",
    "AdapterError",
    "ApplicationDefinition",
    "ApplicationRouter",
    "ApplicationRuntime",
    "AssemblyError",
    "AuthenticatedPrincipal",
    "AuthenticationError",
    "Authenticator",
    "AuthorizationError",
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
    "FastAPISecurity",
    "GuardDefinition",
    "GuardPredicate",
    "HttpMethod",
    "Inject",
    "InsufficientScopeError",
    "InterceptorDefinition",
    "InterceptorHandler",
    "InvalidTokenError",
    "JwtIssuer",
    "JwtKeyResolver",
    "JwtKeySet",
    "JwtVerifier",
    "LifecycleDefinition",
    "Lifespan",
    "MissingCredentialsError",
    "PrincipalPolicy",
    "ProviderDefinition",
    "ProviderFactory",
    "RequestContext",
    "ResolutionError",
    "RouteDefinition",
    "RuntimeClosedError",
    "Scope",
    "SecurityDependencyError",
    "SecurityError",
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
    "require_roles",
    "require_scopes",
    "route",
]
