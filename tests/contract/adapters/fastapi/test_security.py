from typing import Annotated

from dishka import Provider, Scope, provide
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from fastapi_fin.adapters import FastAPIIntegration, FastAPISecurity
from fastapi_fin.errors import AssemblyError
from fastapi_fin.modules import FinProxy, Module
from fastapi_fin.security import (
    AuthenticatedPrincipal,
    JwtIssuer,
    JwtVerifier,
    TokenAuthenticator,
    require_roles,
)

KEY = "k" * 32


class AuthProvider(Provider):
    @provide(scope=Scope.APP)
    def verifier(self) -> TokenAuthenticator:
        return JwtVerifier(
            key=KEY,
            algorithms=("HS256",),
            issuer="https://issuer.example",
            audience="api",
        )


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def build_security() -> tuple[JwtIssuer, FastAPISecurity, FastAPI]:
    issuer = JwtIssuer(
        key=KEY,
        algorithm="HS256",
        issuer="https://issuer.example",
        audience="api",
    )
    fin = FinProxy(
        modules=(Module("auth", providers=(AuthProvider(),), exports=(TokenAuthenticator,)),),
    )
    security = FastAPISecurity(
        token_url="/token",  # noqa: S106 — endpoint path, not a credential.
        scopes={"users:read": "Read users"},
    )
    return issuer, security, FastAPI(lifespan=FastAPIIntegration(fin).lifespan)


def test_fastapi_security_authenticates_bearer_and_documents_scopes() -> None:
    issuer, security, app = build_security()

    @app.get("/me")
    def read_me(
        principal: Annotated[
            AuthenticatedPrincipal,
            security.principal_marker(scopes=("users:read",)),
        ],
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    token = issuer.issue("user-1", scopes=("users:read",))

    with TestClient(app) as client:
        missing = client.get("/me")
        invalid = client.get("/me", headers=bearer("invalid"))
        valid = client.get("/me", headers=bearer(token))

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401
    assert valid.status_code == 200
    assert valid.json() == {"subject": "user-1"}
    operation = app.openapi()["paths"]["/me"]["get"]
    assert operation["security"] == [{"OAuth2PasswordBearer": ["users:read"]}]


def test_fastapi_security_rejects_insufficient_scope_with_403() -> None:
    issuer, security, app = build_security()

    @app.get("/users")
    def list_users(
        _principal: Annotated[
            AuthenticatedPrincipal,
            security.principal_marker(scopes=("users:read",)),
        ],
    ) -> dict[str, str]:
        return {"status": "ok"}

    token = issuer.issue("user-1")
    with TestClient(app) as client:
        response = client.get("/users", headers=bearer(token))

    assert response.status_code == 403
    assert "insufficient_scope" in response.headers["www-authenticate"]


def test_fastapi_security_require_marker_enforces_roles() -> None:
    issuer, security, app = build_security()
    admin_policy = require_roles("admin")
    admin_marker = security.require(admin_policy)

    @app.get("/managed")
    def managed_area(
        principal: Annotated[AuthenticatedPrincipal, admin_marker],
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    user_token = issuer.issue("user-1")
    admin_token = issuer.issue("user-1", roles=("admin",))

    with TestClient(app) as client:
        forbidden = client.get("/managed", headers=bearer(user_token))
        allowed = client.get("/managed", headers=bearer(admin_token))

    assert forbidden.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json() == {"subject": "user-1"}


def test_fastapi_security_scope_descriptions_are_read_only() -> None:
    security = FastAPISecurity(scopes={"users:read": "Read users"})

    with pytest.raises(TypeError):
        security.scopes["users:write"] = "Write users"  # ty: ignore[invalid-assignment]


@pytest.mark.anyio
async def test_fastapi_security_requires_exported_token_authenticator_at_startup() -> None:
    integration = FastAPIIntegration(FinProxy())
    app = FastAPI(lifespan=integration.lifespan)
    security = FastAPISecurity()

    @app.get("/me")
    def read_me(
        principal: Annotated[AuthenticatedPrincipal, security.principal_marker()],
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    with pytest.raises(AssemblyError, match=r"/me.*TokenAuthenticator.*not an exported contract"):
        async with integration.lifespan(app):
            pass
