"""FastAPI-Fin: contract-first dishka dependency injection for FastAPI."""

from importlib import import_module
from typing import TYPE_CHECKING

from .container import build_container, open_container
from .errors import AdapterError, AssemblyError, DefinitionError, FastAPIFinError
from .modules import FinComposition, Module
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
    TokenAuthenticator,
    require_roles,
    require_scopes,
)

if TYPE_CHECKING:
    from .adapters import CONTAINER_STATE_KEY, FastAPIIntegration, FastAPISecurity, Inject

__version__ = "0.9.2"


def __getattr__(name: str) -> object:
    """Load FastAPI-dependent exports only when requested."""
    if name in {"CONTAINER_STATE_KEY", "FastAPIIntegration", "FastAPISecurity", "Inject"}:
        module = import_module(".adapters", __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "CONTAINER_STATE_KEY",
    "AdapterError",
    "AssemblyError",
    "AuthenticatedPrincipal",
    "AuthenticationError",
    "AuthorizationError",
    "DefinitionError",
    "FastAPIFinError",
    "FastAPIIntegration",
    "FastAPISecurity",
    "FinComposition",
    "Inject",
    "InsufficientScopeError",
    "InvalidTokenError",
    "JwtIssuer",
    "JwtKeyResolver",
    "JwtKeySet",
    "JwtVerifier",
    "MissingCredentialsError",
    "Module",
    "PrincipalPolicy",
    "SecurityDependencyError",
    "SecurityError",
    "TokenAuthenticator",
    "__version__",
    "build_container",
    "open_container",
    "require_roles",
    "require_scopes",
]
