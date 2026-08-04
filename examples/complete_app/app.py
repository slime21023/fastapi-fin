"""Application assembly and executable demo for the complete Task API."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import (
    ApplicationDefinition,
    LifecycleDefinition,
    Scope,
    provide,
)
from fastapi_fin.features import InterceptorDefinition

from . import lifecycle, policies, providers
from .routes import router as task_router


def build_app() -> FastAPI:
    definition = ApplicationDefinition(
        routes=task_router,
        providers=(
            provide(
                providers.TaskRepository,
                scope=Scope.APPLICATION,
                eager=True,
                disposer=providers.close_repository,
            ),
            provide(
                providers.TaskService,
                dependencies=(providers.TaskRepository,),
                scope=Scope.REQUEST,
                disposer=providers.close_service,
            ),
        ),
        interceptors=(InterceptorDefinition(policies.audit, name="audit"),),
        lifecycle=LifecycleDefinition(
            startup=(lifecycle.startup,),
            shutdown=(lifecycle.shutdown,),
        ),
    )
    return FastAPIAdapter.create_app(
        definition,
        title="FastAPI-Fin complete Task API",
        version="1.0.1",
    )


def run_demo() -> None:
    policies.reset_state()
    providers.reset_state()
    lifecycle.reset_state()

    with TestClient(build_app()) as client:
        empty = client.get("/tasks")
        forbidden = client.post("/tasks", json={"title": "Learn FastAPI-Fin"})
        created = client.post(
            "/tasks",
            json={"title": "Learn FastAPI-Fin"},
            headers={"X-Role": "admin"},
        )
        tasks = client.get("/tasks")

    assert empty.status_code == 200
    assert empty.json() == []
    assert forbidden.status_code == 403
    assert created.status_code == 201
    assert created.json() == {
        "id": 1,
        "title": "Learn FastAPI-Fin",
        "completed": False,
    }
    assert tasks.json() == [created.json()]
    assert policies.audit_log == ["request", "request", "request"]
    assert lifecycle.events == ["started", "stopped"]
    assert providers.cleanup_log == [
        "service-closed",
        "service-closed",
        "service-closed",
        "service-closed",
        "repository-closed",
    ]
    print("complete_app: OK")
