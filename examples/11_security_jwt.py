"""Use a signed JWT bearer token with FastAPI scopes and a typed principal."""

from typing import Annotated

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin.adapters import FastAPIAdapter, FastAPISecurity
from fastapi_fin.application import ApplicationDefinition, ApplicationRouter
from fastapi_fin.security import AuthenticatedPrincipal, JwtIssuer, JwtVerifier

KEY = "k" * 32
TOKEN_URL = "/token"  # noqa: S105


def build_app() -> tuple[FastAPI, str]:
    issuer = JwtIssuer(
        key=KEY,
        algorithm="HS256",
        issuer="https://issuer.example",
        audience="task-api",
    )
    verifier = JwtVerifier(
        key=KEY,
        algorithms=("HS256",),
        issuer="https://issuer.example",
        audience="task-api",
    )
    security = FastAPISecurity(
        verifier.authenticate,
        token_url=TOKEN_URL,
        scopes={"tasks:read": "Read tasks"},
    )
    router = ApplicationRouter(prefix="/tasks", tags=("tasks",))

    @router.get("/")
    def list_tasks(
        principal: Annotated[
            AuthenticatedPrincipal,
            security.principal_marker(scopes=("tasks:read",)),
        ],
    ) -> dict[str, str]:
        return {"subject": principal.subject}

    token = issuer.issue("user-1", scopes=("tasks:read",))
    return FastAPIAdapter.create_app(ApplicationDefinition(routes=router)), token


def main() -> None:
    app, token = build_app()
    with TestClient(app) as client:
        unauthorized = client.get("/tasks/")
        authorized = client.get(
            "/tasks/",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200
    assert authorized.json() == {"subject": "user-1"}
    print("11_security_jwt: OK")


if __name__ == "__main__":
    main()
