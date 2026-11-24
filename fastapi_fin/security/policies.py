"""Framework-independent authorization policies."""

from attrs import field, frozen

from .._validation import bool_validator, text_converter, text_tuple_converter
from .claims import AuthenticatedPrincipal
from .errors import AuthorizationError, InsufficientScopeError


@frozen
class PrincipalPolicy:
    """Immutable scope and role requirements for an authenticated principal."""

    scopes: tuple[str, ...] = field(default=(), converter=text_tuple_converter("required scopes"))
    roles: tuple[str, ...] = field(default=(), converter=text_tuple_converter("required roles"))
    all_roles: bool = field(default=True, validator=bool_validator("all_roles"))
    name: str = field(default="principal-policy", converter=text_converter("policy name"))

    def allows(self, principal: AuthenticatedPrincipal) -> bool:
        """Return whether a principal satisfies this policy."""
        if not isinstance(principal, AuthenticatedPrincipal):
            return False
        return not self._missing_scopes(principal) and self._has_required_roles(principal)

    def _missing_scopes(self, principal: AuthenticatedPrincipal) -> tuple[str, ...]:
        granted = frozenset(principal.scopes)
        return tuple(scope for scope in self.scopes if scope not in granted)

    def _has_required_roles(self, principal: AuthenticatedPrincipal) -> bool:
        if not self.roles:
            return True
        required, granted = frozenset(self.roles), frozenset(principal.roles)
        return required <= granted if self.all_roles else not required.isdisjoint(granted)

    def enforce(self, principal: AuthenticatedPrincipal) -> None:
        """Raise a typed authorization error when the policy is not satisfied."""
        if not isinstance(principal, AuthenticatedPrincipal):
            raise AuthorizationError("authenticated principal is required")
        if missing_scopes := self._missing_scopes(principal):
            raise InsufficientScopeError(missing_scopes)
        if not self._has_required_roles(principal):
            raise AuthorizationError("principal is not allowed")


def require_scopes(*scopes: str, name: str = "required-scopes") -> PrincipalPolicy:
    """Create a policy requiring every listed OAuth scope."""
    return PrincipalPolicy(scopes=scopes, name=name)


def require_roles(
    *roles: str,
    all_roles: bool = True,
    name: str = "required-roles",
) -> PrincipalPolicy:
    """Create a policy requiring all or any of the listed roles."""
    return PrincipalPolicy(roles=roles, all_roles=all_roles, name=name)


__all__ = ["PrincipalPolicy", "require_roles", "require_scopes"]
