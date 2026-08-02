"""Use create_app() to compose application lifecycle events."""

from fastapi.testclient import TestClient

from fastapi_fin import (
    ApplicationStarted,
    ApplicationStopping,
    EventDispatcher,
    FastAPIAdapter,
)
from fastapi_fin.application import ApplicationRegistry

events: list[str] = []
dispatcher = (
    EventDispatcher()
    .subscribe(ApplicationStarted, lambda _event: events.append("started"))
    .subscribe(ApplicationStopping, lambda _event: events.append("stopping"))
)


def build_app():
    return FastAPIAdapter.create_app(
        ApplicationRegistry(),
        event_dispatcher=dispatcher,
    )


if __name__ == "__main__":
    with TestClient(build_app()):
        assert events == ["started"]

    assert events == ["started", "stopping"]
    print("04_lifecycle_events: OK")
