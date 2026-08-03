"""Define explicit routes and mount them into an existing stateless FastAPI app."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationDefinition, route


def get_user(user_id: int) -> dict[str, int]:
    return {"user_id": user_id}


def build_app() -> FastAPI:
    app = FastAPI(title="FastAPI-first example")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    definition = ApplicationDefinition(
        routes=(route("/api/users/{user_id}", get_user),),
    )
    FastAPIAdapter.mount(app, definition)
    return app


if __name__ == "__main__":
    app = build_app()
    with TestClient(app) as client:
        native_response = client.get("/health")
        response = client.get("/api/users/42")

    assert native_response.status_code == 200
    assert native_response.json() == {"status": "ok"}
    assert response.status_code == 200
    assert response.json() == {"user_id": 42}
    assert "/api/users/{user_id}" in app.openapi()["paths"]
    print("01_minimal_routes: OK")
