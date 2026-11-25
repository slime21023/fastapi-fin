"""Revoke tokens by JWT ID and rate-limit a route with overridable services."""

from collections import Counter
from secrets import token_urlsafe
from typing import Annotated, Protocol

from dishka import Provider, Scope, provide
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from fastapi_fin import (
    Application,
    AuthenticatedPrincipal,
    FastAPIIntegration,
    FastAPISecurity,
    Inject,
    InvalidTokenError,
    JwtIssuer,
    JwtVerifier,
    Module,
    TokenAuthenticator,
)

ISSUER_URL = "https://issuer.example"
REQUESTS_PER_CLIENT = 3
SECURITY = FastAPISecurity()


class RevokedTokens(Protocol):
    def revoke(self, token_id: str) -> None: ...

    def is_revoked(self, token_id: str) -> bool: ...


class RequestBudget(Protocol):
    def consume(self, client: str) -> bool: ...


class InMemoryRevokedTokens:
    """One copy per worker; production stores keep each ID until the token's exp."""

    def __init__(self) -> None:
        self._token_ids: set[str] = set()

    def revoke(self, token_id: str) -> None:
        self._token_ids.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        return token_id in self._token_ids


class InMemoryRequestBudget:
    """Counts requests per client with no time window; production uses a shared store."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._used: Counter[str] = Counter()

    def consume(self, client: str) -> bool:
        self._used[client] += 1
        return self._used[client] <= self._limit


class RevocationCheckingAuthenticator:
    def __init__(self, verifier: JwtVerifier, revoked: RevokedTokens) -> None:
        self._verifier = verifier
        self._revoked = revoked

    def authenticate(self, token: str) -> AuthenticatedPrincipal:
        # Verify the signature first so forged tokens never reach the store.
        principal = self._verifier.authenticate(token)
        if principal.token_id is not None and self._revoked.is_revoked(principal.token_id):
            raise InvalidTokenError("JWT has been revoked")
        return principal


class StateProvider(Provider):
    revoked = provide(InMemoryRevokedTokens, provides=RevokedTokens, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def budget(self) -> RequestBudget:
        return InMemoryRequestBudget(limit=REQUESTS_PER_CLIENT)


class AuthProvider(Provider):
    def __init__(self, verifier: JwtVerifier) -> None:
        super().__init__()
        self._verifier = verifier

    @provide(scope=Scope.APP)
    def authenticator(self, revoked: RevokedTokens) -> TokenAuthenticator:
        return RevocationCheckingAuthenticator(self._verifier, revoked)


async def enforce_rate_limit(request: Request, budget: Inject[RequestBudget]) -> None:
    client = request.client.host if request.client is not None else "unknown"
    if not budget.consume(client):
        raise HTTPException(
            status_code=429, detail="rate limit exceeded", headers={"Retry-After": "60"}
        )


def create_app(application: Application) -> FastAPI:
    app = FastAPI(lifespan=FastAPIIntegration(application).lifespan)

    @app.get("/me", dependencies=[Depends(enforce_rate_limit)])
    async def read_me(
        principal: Annotated[AuthenticatedPrincipal, SECURITY.principal_marker()],
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    @app.post("/logout")
    async def logout(
        principal: Annotated[AuthenticatedPrincipal, SECURITY.principal_marker()],
        revoked: Inject[RevokedTokens],
    ) -> dict[str, str]:
        if principal.token_id is not None:
            revoked.revoke(principal.token_id)
        return {"status": "logged out"}

    return app


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def main() -> None:
    key = token_urlsafe(32)
    issuer = JwtIssuer(key=key, algorithm="HS256", issuer=ISSUER_URL, audience="api")
    verifier = JwtVerifier(key=key, algorithms=("HS256",), issuer=ISSUER_URL, audience="api")
    application = Application(
        modules=(
            Module(
                "state",
                providers=(StateProvider(),),
                exports=(RevokedTokens, RequestBudget),
            ),
            Module(
                "auth",
                providers=(AuthProvider(verifier),),
                exports=(TokenAuthenticator,),
                requires=(RevokedTokens,),
            ),
        )
    )

    with TestClient(create_app(application)) as client:
        first = bearer(issuer.issue("user-1"))
        assert client.get("/me", headers=first).json() == {"subject": "user-1"}
        assert client.post("/logout", headers=first).json() == {"status": "logged out"}
        revoked = client.get("/me", headers=first)
        assert revoked.status_code == 401
        assert revoked.headers["www-authenticate"] == "Bearer"

        second = bearer(issuer.issue("user-1"))
        assert client.get("/me", headers=second).status_code == 200
        limited = client.get("/me", headers=second)
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "60"

    leaked_id = "leaked-jwt-id"
    preloaded = InMemoryRevokedTokens()
    preloaded.revoke(leaked_id)
    leaked = bearer(issuer.issue("user-1", token_id=leaked_id))
    with TestClient(create_app(application.with_overrides({RevokedTokens: preloaded}))) as client:
        assert client.get("/me", headers=leaked).status_code == 401

    print("08_revocation_and_rate_limits: OK")


if __name__ == "__main__":
    main()
