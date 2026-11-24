"""Framework-independent authentication and authorization primitives."""

from .claims import AuthenticatedPrincipal
from .contracts import TokenAuthenticator
from .errors import (
    AuthenticationError,
    AuthorizationError,
    InsufficientScopeError,
    InvalidTokenError,
    MissingCredentialsError,
    SecurityDependencyError,
    SecurityError,
)
from .jwt import JwtIssuer, JwtKeyResolver, JwtKeySet, JwtVerifier
from .policies import PrincipalPolicy, require_roles, require_scopes

__all__ = [
    "AuthenticatedPrincipal",
    "AuthenticationError",
    "AuthorizationError",
    "InsufficientScopeError",
    "InvalidTokenError",
    "JwtIssuer",
    "JwtKeyResolver",
    "JwtKeySet",
    "JwtVerifier",
    "MissingCredentialsError",
    "PrincipalPolicy",
    "SecurityDependencyError",
    "SecurityError",
    "TokenAuthenticator",
    "require_roles",
    "require_scopes",
]
