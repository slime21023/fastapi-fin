"""Resolve a provider-backed controller in a FastAPI endpoint."""

from fastapi.testclient import TestClient

from fastapi_fin import ApplicationRegistry, Scope
from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import controller, get


class GreetingService:
    def greet(self, name: str) -> str:
        return f"Hello, {name}!"


@controller(prefix="/greetings")
class GreetingController:
    def __init__(self, service: GreetingService) -> None:
        self.service = service

    @get("/{name}")
    def greet(self, name: str) -> dict[str, str]:
        return {"message": self.service.greet(name)}


def build_app():
    registry = (
        ApplicationRegistry()
        .controller(GreetingController)
        .provide(GreetingService, scope=Scope.SINGLETON)
    )
    return FastAPIAdapter.create_app(registry)


if __name__ == "__main__":
    app = build_app()

    with TestClient(app) as client:
        response = client.get("/greetings/Codex")

    assert response.status_code == 200
    assert response.json() == {"message": "Hello, Codex!"}
    print("02_dependency_injection: OK")
