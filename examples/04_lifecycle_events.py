"""Use explicit lifecycle hooks owned by the FastAPI adapter."""

from fastapi.testclient import TestClient

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationDefinition, LifecycleDefinition

events: list[str] = []


def startup() -> None:
    events.append("started")


def shutdown() -> None:
    events.append("stopped")


def build_app():
    definition = ApplicationDefinition(
        lifecycle=LifecycleDefinition(startup=(startup,), shutdown=(shutdown,)),
    )
    return FastAPIAdapter.create_app(definition)


if __name__ == "__main__":
    with TestClient(build_app()):
        assert events == ["started"]

    assert events == ["started", "stopped"]
    print("04_lifecycle_events: OK")
