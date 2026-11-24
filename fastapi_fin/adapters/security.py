"""FastAPI security boundary for framework-independent authenticators."""

from collections.abc import Callable, Mapping
from inspect import isawaitable
from typing import Any

from fastapi import Depends, HTTPException, Security
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
        if token_url is not None and (not isinstance(token_url, str) or not token_url.strip()):
            raise AdapterError("security token_url must be non-empty text")
        if scopes is None:
            scopes = {}
        if not isinstance(scopes, Mapping):
            raise AdapterError("security scopes must be a mapping")
        if not all(
            isinstance(name, str) and name.strip() and isinstance(summary, str) and summary.strip()
            for name, summary in scopes.items()
        ):
            raise AdapterError("security scopes must map non-empty names to descriptions")
        self.scopes = dict(scopes)
        if token_url is None:
            self.scheme = HTTPBearer(
                auto_error=False,
                scheme_name=scheme_name,
                description=description,
            )
        else:
            self.scheme = OAuth2PasswordBearer(
                tokenUrl=token_url,
                scopes=self.scopes,
                scheme_name=scheme_name,
                description=description,
                auto_error=False,
            )
        self.current_principal = self._build_current_principal()

    def principal_marker(self, *, scopes: tuple[str, ...] = ()) -> Any:
        """Return a FastAPI ``Security`` marker for endpoint parameters."""
        self._validate_scopes(scopes)
        return Security(self.current_principal, scopes=list(scopes))

    def require(self, policy: PrincipalPolicy) -> Any:
        """Return an endpoint marker that authenticates and enforces a policy."""
        if not isinstance(policy, PrincipalPolicy):
            raise AdapterError("security policy must be a PrincipalPolicy")
        self._validate_scopes(policy.scopes)
        policy_dependency = Security(
            self.current_principal,
            scopes=list(policy.scopes),
        )

        async def enforce_policy(
            principal: AuthenticatedPrincipal = policy_dependency,
        ) -> AuthenticatedPrincipal:
            try:
                policy.enforce(principal)
            except InsufficientScopeError as error:
                raise _insufficient_scope_error(error.required_scopes) from error
            except AuthorizationError as error:
                raise _authorization_error() from error
            return principal

        return Depends(enforce_policy)

    def _build_current_principal(self) -> Callable[..., Any]:
        scheme_dependency = Depends(self.scheme)

        async def resolve(
            security_scopes: SecurityScopes,
            authenticator: Inject[TokenAuthenticator],
            credentials: Any = scheme_dependency,
        ) -> AuthenticatedPrincipal:
            token = (
                credentials
                if isinstance(credentials, str)
                else getattr(credentials, "credentials", None)
            )
            if not isinstance(token, str) or not token.strip():
                raise _authentication_error()
            try:
                principal = authenticator.authenticate(token)
                if isawaitable(principal):
                    principal = await principal
            except AuthenticationError as error:
                raise _authentication_error() from error
            if not isinstance(principal, AuthenticatedPrincipal):
                raise _authentication_error()
            required_scopes = tuple(security_scopes.scopes)
            missing_scopes = tuple(
                scope for scope in required_scopes if not principal.has_scope(scope)
            )
            if missing_scopes:
                raise _insufficient_scope_error(required_scopes)
            return principal

        return resolve

    def _validate_scopes(self, scopes: tuple[str, ...]) -> None:
        if not all(isinstance(scope, str) and scope.strip() for scope in scopes):
            raise AdapterError("security scopes must contain non-empty strings")
        unknown = set(scopes).difference(self.scopes)
        if self.scopes and unknown:
            raise AdapterError(f"security scopes are not declared: {sorted(unknown)!r}")


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
