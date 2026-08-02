"""Start with FastAPI, then add FastAPI-Fin routes to the existing app."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import MetadataRegistry, controller, get, module


@controller(prefix="/users")
class UserController:
    @get("/{user_id}")
    def get_user(self, user_id: int) -> dict[str, int]:
        return {"user_id": user_id}


@module(prefix="/api", controllers=(UserController,))
class ApiModule:
    pass


def build_app() -> FastAPI:
    app = FastAPI(title="FastAPI-first example")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    registry = MetadataRegistry().register_module(ApiModule)
    FastAPIAdapter(app).include(registry)
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
