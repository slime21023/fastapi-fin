"""Use explicit providers and an application-scoped dependency."""

from fastapi.testclient import TestClient

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationDefinition, Scope, inject, provide, route


class GreetingService:
    def greet(self, name: str) -> str:
        return f"Hello, {name}!"


GREETING_SERVICE = inject(GreetingService)


def greet(
    name: str,
    service: GreetingService = GREETING_SERVICE,
) -> dict[str, str]:
    return {"message": service.greet(name)}


def build_app():
    definition = ApplicationDefinition(
        routes=(route("/greetings/{name}", greet),),
        providers=(provide(GreetingService, scope=Scope.APPLICATION, eager=True),),
    )
    return FastAPIAdapter.create_app(definition)


if __name__ == "__main__":
    with TestClient(build_app()) as client:
        response = client.get("/greetings/Codex")

    assert response.status_code == 200
    assert response.json() == {"message": "Hello, Codex!"}
    print("02_dependency_injection: OK")
