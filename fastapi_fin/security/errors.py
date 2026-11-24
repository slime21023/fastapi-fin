"""Framework-independent security errors."""

from collections.abc import Iterable

from ..errors import FastAPIFinError


class SecurityError(FastAPIFinError):
    """Base class for security failures."""


class SecurityDependencyError(SecurityError):
    """Raised when an optional security dependency is not installed."""


class AuthenticationError(SecurityError):
    """Raised when credentials are missing or cannot be authenticated."""


class MissingCredentialsError(AuthenticationError):
    """Raised when a protected operation has no credentials."""


class InvalidTokenError(AuthenticationError):
    """Raised when a token fails structural or cryptographic validation."""


class AuthorizationError(SecurityError):
    """Raised when an authenticated principal is not allowed to act."""


class InsufficientScopeError(AuthorizationError):
    """Raised when a principal lacks one or more required OAuth scopes."""

    def __init__(self, required_scopes: Iterable[str]) -> None:
        """Record the scopes required by the rejected operation."""
        self.required_scopes = tuple(required_scopes)
        super().__init__("insufficient scope")


__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "InsufficientScopeError",
    "InvalidTokenError",
    "MissingCredentialsError",
    "SecurityDependencyError",
    "SecurityError",
]
