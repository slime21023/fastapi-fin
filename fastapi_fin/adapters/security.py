"""FastAPI security boundary for framework-independent authenticators."""

from collections.abc import Awaitable, Callable, Mapping
from inspect import isawaitable

from fastapi import Depends, HTTPException, Security
from fastapi.params import Depends as DependsMarker
from fastapi.params import Security as SecurityMarker
from fastapi.security import HTTPBearer, OAuth2PasswordBearer, SecurityScopes

from ..errors import AdapterError
from ..security import (
    AuthenticatedPrincipal,
    AuthenticationError,
    AuthorizationError,
    InsufficientScopeError,
    PrincipalPolicy,
    TokenAuthenticator,
)
from .fastapi import Inject


class FastAPISecurity:
    """Authenticate FastAPI dependencies using the exported token authenticator."""

    def __init__(
        self,
        *,
        token_url: str | None = None,
        scopes: Mapping[str, str] | None = None,
        scheme_name: str | None = None,
        description: str | None = None,
    ) -> None:
        """Configure HTTP bearer or OAuth2 password bearer authentication."""
        if token_url is not None and (not isinstance(token_url, str) or not token_url.strip()):
            raise AdapterError("security token_url must be non-empty text")
        self.scopes = _validated_scope_descriptions(scopes)
        self.scheme = _build_scheme(token_url, self.scopes, scheme_name, description)
        self.current_principal = self._build_current_principal()

    def principal_marker(self, *, scopes: tuple[str, ...] = ()) -> SecurityMarker:
        """Return a FastAPI ``Security`` marker for endpoint parameters."""
        self._validate_scopes(scopes)
        return Security(self.current_principal, scopes=list(scopes))

    def require(self, policy: PrincipalPolicy) -> DependsMarker:
        """Return an endpoint marker that authenticates and enforces a policy."""
        if not isinstance(policy, PrincipalPolicy):
            raise AdapterError("security policy must be a PrincipalPolicy")
        self._validate_scopes(policy.scopes)
        principal_dependency = Security(self.current_principal, scopes=list(policy.scopes))

        async def enforce_policy(
            principal: AuthenticatedPrincipal = principal_dependency,
        ) -> AuthenticatedPrincipal:
            try:
                policy.enforce(principal)
            except InsufficientScopeError as error:
                raise _insufficient_scope_error(error.required_scopes) from error
            except AuthorizationError as error:
                raise _authorization_error() from error
            return principal

        return Depends(enforce_policy)

    def _build_current_principal(self) -> Callable[..., Awaitable[AuthenticatedPrincipal]]:
        credentials_dependency = Depends(self.scheme)

        async def resolve(
            security_scopes: SecurityScopes,
            authenticator: Inject[TokenAuthenticator],
            credentials: object = credentials_dependency,
        ) -> AuthenticatedPrincipal:
            token = _bearer_token(credentials)
            principal = await _authenticate(authenticator, token)
            required_scopes = tuple(security_scopes.scopes)
            if set(required_scopes).difference(principal.scopes):
                raise _insufficient_scope_error(required_scopes)
            return principal

        return resolve

    def _validate_scopes(self, scopes: tuple[str, ...]) -> None:
        if not all(isinstance(scope, str) and scope.strip() for scope in scopes):
            raise AdapterError("security scopes must contain non-empty strings")
        undeclared = set(scopes).difference(self.scopes)
        if self.scopes and undeclared:
            raise AdapterError(f"security scopes are not declared: {sorted(undeclared)!r}")


def _validated_scope_descriptions(scopes: Mapping[str, str] | None) -> dict[str, str]:
    if scopes is None:
        return {}
    if not isinstance(scopes, Mapping):
        raise AdapterError("security scopes must be a mapping")
    if not all(_is_text(name) and _is_text(summary) for name, summary in scopes.items()):
        raise AdapterError("security scopes must map non-empty names to descriptions")
    return dict(scopes)


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _build_scheme(
    token_url: str | None,
    scopes: dict[str, str],
    scheme_name: str | None,
    description: str | None,
) -> HTTPBearer | OAuth2PasswordBearer:
    if token_url is None:
        return HTTPBearer(auto_error=False, scheme_name=scheme_name, description=description)
    return OAuth2PasswordBearer(
        tokenUrl=token_url,
        scopes=scopes,
        scheme_name=scheme_name,
        description=description,
        auto_error=False,
    )


def _bearer_token(credentials: object) -> str:
    """Extract the raw token from either scheme's credentials, or reject the request."""
    token = (
        credentials if isinstance(credentials, str) else getattr(credentials, "credentials", None)
    )
    if not isinstance(token, str) or not token.strip():
        raise _authentication_error()
    return token


async def _authenticate(authenticator: TokenAuthenticator, token: str) -> AuthenticatedPrincipal:
    try:
        principal = authenticator.authenticate(token)
        if isawaitable(principal):
            principal = await principal
    except AuthenticationError as error:
        raise _authentication_error() from error
    if not isinstance(principal, AuthenticatedPrincipal):
        raise _authentication_error()
    return principal


def _authentication_error() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _insufficient_scope_error(scopes: tuple[str, ...]) -> HTTPException:
    scope_value = " ".join(scopes)
    return HTTPException(
        status_code=403,
        detail="insufficient scope",
        headers={
            "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scope_value}"',
        },
    )


def _authorization_error() -> HTTPException:
    return HTTPException(status_code=403, detail="forbidden")


__all__ = ["FastAPISecurity"]
