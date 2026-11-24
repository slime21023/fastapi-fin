"""Framework-independent contracts for security providers."""

from collections.abc import Awaitable
from typing import Protocol

from .claims import AuthenticatedPrincipal


class TokenAuthenticator(Protocol):
    """Authenticate a bearer token to obtain its principal."""

    def authenticate(
        self, token: str
    ) -> AuthenticatedPrincipal | Awaitable[AuthenticatedPrincipal]:
        """Return the authenticated principal or raise an authentication error."""
        ...


__all__ = ["TokenAuthenticator"]
