"""Resolve a service from the attrs-based container in a FastAPI endpoint."""

from fastapi import Depends
from fastapi.testclient import TestClient

from fastapi_fin import (
    ContainerRuntime,
    ContainerSnapshot,
    FastAPIAdapter,
    Lifecycle,
    container_dependency,
    controller,
    get,
)
from fastapi_fin.application import MetadataRegistry


class GreetingService:
    def greet(self, name: str) -> str:
        return f"Hello, {name}!"


runtime = ContainerRuntime(
    snapshot=ContainerSnapshot().bind(
        GreetingService,
        GreetingService,
        lifecycle=Lifecycle.SINGLETON,
    )
)
greeting_dependency = container_dependency(runtime, GreetingService)
greeting_dependency_marker = Depends(greeting_dependency)


@controller(prefix="/greetings")
class GreetingController:
    @get("/{name}")
    def greet(
        self,
        name: str,
        service: GreetingService = greeting_dependency_marker,
    ) -> dict[str, str]:
        return {"message": service.greet(name)}


def build_app():
    registry = MetadataRegistry().register_controller(GreetingController)
    return FastAPIAdapter.create_app(registry, container_runtime=runtime)


if __name__ == "__main__":
    app = build_app()

    with TestClient(app) as client:
        response = client.get("/greetings/Codex")

    assert response.status_code == 200
    assert response.json() == {"message": "Hello, Codex!"}
    print("02_dependency_injection: OK")
