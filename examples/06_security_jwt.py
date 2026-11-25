"""Verify JWT bearer tokens using an exported TokenAuthenticator contract."""

from secrets import token_urlsafe
from typing import Annotated

from dishka import Provider, Scope, provide
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin import (
    AuthenticatedPrincipal,
    FastAPIIntegration,
    FastAPISecurity,
    FinProxy,
    JwtIssuer,
    JwtVerifier,
    Module,
    TokenAuthenticator,
)


class AuthProvider(Provider):
    def __init__(self, verifier: JwtVerifier) -> None:
        super().__init__()
        self._verifier = verifier

    @provide(scope=Scope.APP)
    def authenticator(self) -> TokenAuthenticator:
        return self._verifier


def main() -> None:
    key = token_urlsafe(32)
    issuer_url = "https://issuer.example"
    issuer = JwtIssuer(key=key, algorithm="HS256", issuer=issuer_url, audience="api")
    verifier = JwtVerifier(key=key, algorithms=("HS256",), issuer=issuer_url, audience="api")
    auth = Module("auth", providers=(AuthProvider(verifier),), exports=(TokenAuthenticator,))
    app = FastAPI(lifespan=FastAPIIntegration(FinProxy(modules=(auth,))).lifespan)
    security = FastAPISecurity(token_url=f"{issuer_url}/token", scopes={"users:read": "Read users"})

    @app.get("/me")
    async def read_me(
        principal: Annotated[
            AuthenticatedPrincipal,
            security.principal_marker(scopes=("users:read",)),
        ],
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    with TestClient(app) as client:
        missing = client.get("/me")
        assert missing.status_code == 401
        assert missing.headers["www-authenticate"] == "Bearer"

        unscoped_token = issuer.issue("user-1")
        forbidden = client.get("/me", headers={"Authorization": f"Bearer {unscoped_token}"})
        assert forbidden.status_code == 403
        assert "insufficient_scope" in forbidden.headers["www-authenticate"]

        token = issuer.issue("user-1", scopes=("users:read",))
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.json() == {"subject": "user-1"}

    print("06_security_jwt: OK")


if __name__ == "__main__":
    main()
