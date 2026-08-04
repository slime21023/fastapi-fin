"""Framework-independent authorization policies."""

from collections.abc import Iterable

from attrs import define, field

from .._validation import bool_validator
from ..errors import DefinitionError
from .claims import AuthenticatedPrincipal
from .errors import AuthorizationError, InsufficientScopeError


def _normalize_requirements(values: Iterable[str], label: str) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    try:
        normalized = tuple(values)
    except TypeError as error:
        raise DefinitionError(f"{label} must be iterable") from error
    if not all(isinstance(value, str) and value.strip() for value in normalized):
        raise DefinitionError(f"{label} must contain non-empty strings")
    return tuple(dict.fromkeys(value.strip() for value in normalized))


@define(frozen=True, slots=True)
class PrincipalPolicy:
    """Immutable scope and role requirements for an authenticated principal."""

    scopes: tuple[str, ...] = field(
        default=(),
        converter=lambda value: _normalize_requirements(value, "required scopes"),
    )
    roles: tuple[str, ...] = field(
        default=(),
        converter=lambda value: _normalize_requirements(value, "required roles"),
    )
    all_roles: bool = field(default=True, validator=bool_validator("all_roles"))
    name: str = "principal-policy"

    def allows(self, principal: AuthenticatedPrincipal) -> bool:
        """Return whether a principal satisfies this policy."""
        if not isinstance(principal, AuthenticatedPrincipal):
            return False
        if not all(principal.has_scope(scope) for scope in self.scopes):
            return False
        if self.all_roles:
            return all(principal.has_role(role) for role in self.roles)
        return not self.roles or any(principal.has_role(role) for role in self.roles)

    def enforce(self, principal: AuthenticatedPrincipal) -> None:
        """Raise a typed authorization error when the policy is not satisfied."""
        if not isinstance(principal, AuthenticatedPrincipal):
            raise AuthorizationError("authenticated principal is required")
        missing_scopes = tuple(scope for scope in self.scopes if not principal.has_scope(scope))
        if missing_scopes:
            raise InsufficientScopeError(missing_scopes)
        if not self.allows(principal):
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
