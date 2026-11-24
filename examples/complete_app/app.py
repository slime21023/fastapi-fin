"""Application assembly and executable demo for the complete Task API."""

from secrets import token_hex

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin import Application, FastAPIIntegration, JwtIssuer

from .providers import JWT_AUDIENCE, JWT_ISSUER, auth_module, tasks_module
from .routes import router as task_router


def create_app(application: Application) -> FastAPI:
    app = FastAPI(
        title="FastAPI-Fin complete Task API",
        version="2.0.0",
        lifespan=FastAPIIntegration(application).lifespan,
    )
    app.include_router(task_router)
    return app


def run_demo() -> None:
    signing_key = token_hex(32)
    issuer = JwtIssuer(
        key=signing_key,
        algorithm="HS256",
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
    )
    application = Application(modules=(tasks_module, auth_module(signing_key)))
    user_token = issuer.issue("reader")
    admin_token = issuer.issue("admin", roles=("admin",))
    payload = {"title": "Learn FastAPI-Fin"}

    with TestClient(create_app(application)) as client:
        empty = client.get("/tasks")
        missing = client.post("/tasks", json=payload)
        invalid = client.post("/tasks", json=payload, headers={"Authorization": "Bearer not-a-jwt"})
        forbidden = client.post(
            "/tasks", json=payload, headers={"Authorization": f"Bearer {user_token}"}
        )
        created = client.post(
            "/tasks", json=payload, headers={"Authorization": f"Bearer {admin_token}"}
        )
        tasks = client.get("/tasks")

    assert empty.status_code == 200
    assert empty.json() == []
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401
    assert forbidden.status_code == 403
    assert created.status_code == 201
    assert created.json() == {
        "id": 1,
        "title": "Learn FastAPI-Fin",
        "completed": False,
    }
    assert tasks.status_code == 200
    assert tasks.json() == [created.json()]
    print("complete_app: OK")
