import asyncio
from typing import Annotated, Any

import httpx

from fastapi_fin.adapters import FastAPIAdapter, FastAPISecurity
from fastapi_fin.application import ApplicationDefinition, ApplicationRouter
from fastapi_fin.security import (
    AuthenticatedPrincipal,
    JwtIssuer,
    JwtVerifier,
    require_roles,
)

KEY = "k" * 32


def request(app: Any, path: str, **kwargs: Any) -> httpx.Response:
    async def scenario() -> httpx.Response:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client,
        ):
            return await client.get(path, **kwargs)

    return asyncio.run(scenario())


def build_security() -> tuple[JwtIssuer, FastAPISecurity]:
    issuer = JwtIssuer(
        key=KEY,
        algorithm="HS256",
        issuer="https://issuer.example",
        audience="api",
    )
    verifier = JwtVerifier(
        key=KEY,
        algorithms=("HS256",),
        issuer="https://issuer.example",
        audience="api",
    )
    security = FastAPISecurity(
        verifier.authenticate,
        token_url="/token",
        scopes={"users:read": "Read users"},
    )
    return issuer, security


def test_fastapi_security_authenticates_bearer_and_documents_scopes() -> None:
    issuer, security = build_security()
    router = ApplicationRouter()

    @router.get("/me")
    def read_me(
        principal: Annotated[
            AuthenticatedPrincipal,
            security.principal_marker(scopes=("users:read",)),
        ],
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    app = FastAPIAdapter.create_app(ApplicationDefinition(routes=router))
    token = issuer.issue("user-1", scopes=("users:read",))

    missing = request(app, "/me")
    invalid = request(app, "/me", headers={"Authorization": "Bearer invalid"})
    valid = request(app, "/me", headers={"Authorization": f"Bearer {token}"})

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401
    assert valid.status_code == 200
    assert valid.json() == {"subject": "user-1"}
    operation = app.openapi()["paths"]["/me"]["get"]
    assert operation["security"] == [{"OAuth2PasswordBearer": ["users:read"]}]


def test_fastapi_security_rejects_insufficient_scope_with_403() -> None:
    issuer, security = build_security()
    router = ApplicationRouter()

    @router.get("/users")
    def list_users(
        _principal: Annotated[
            AuthenticatedPrincipal,
            security.principal_marker(scopes=("users:read",)),
        ],
    ) -> dict[str, str]:
        return {"status": "ok"}

    app = FastAPIAdapter.create_app(ApplicationDefinition(routes=router))
    token = issuer.issue("user-1")
    response = request(app, "/users", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert "insufficient_scope" in response.headers["www-authenticate"]


def test_fastapi_security_policy_marker_and_guard_use_authenticated_principal() -> None:
    issuer, security = build_security()
    router = ApplicationRouter()
    admin_policy = require_roles("admin")

    @router.get("/admin", guards=(security.guard(admin_policy),))
    def admin_area(
        _principal: Annotated[AuthenticatedPrincipal, security.principal_marker()],
    ) -> dict[str, str]:
        return {"status": "ok"}

    app = FastAPIAdapter.create_app(ApplicationDefinition(routes=router))
    user_token = issuer.issue("user-1")
    admin_token = issuer.issue("user-1", roles=("admin",))

    forbidden = request(app, "/admin", headers={"Authorization": f"Bearer {user_token}"})
    allowed = request(app, "/admin", headers={"Authorization": f"Bearer {admin_token}"})

    assert forbidden.status_code == 403
    assert allowed.status_code == 200


def test_fastapi_security_require_marker_enforces_roles() -> None:
    issuer, security = build_security()
    router = ApplicationRouter()
    admin_policy = require_roles("admin")
    admin_marker = security.require(admin_policy)

    @router.get("/managed")
    def managed_area(
        principal: AuthenticatedPrincipal = admin_marker,
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    app = FastAPIAdapter.create_app(ApplicationDefinition(routes=router))
    user_token = issuer.issue("user-1")
    admin_token = issuer.issue("user-1", roles=("admin",))

    forbidden = request(app, "/managed", headers={"Authorization": f"Bearer {user_token}"})
    allowed = request(app, "/managed", headers={"Authorization": f"Bearer {admin_token}"})

    assert forbidden.status_code == 403
    assert allowed.status_code == 200
