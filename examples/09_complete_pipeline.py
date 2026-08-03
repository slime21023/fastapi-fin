"""Compose dependency injection, policy execution and managed lifecycle."""

from collections.abc import Awaitable, Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import (
    ApplicationDefinition,
    LifecycleDefinition,
    Scope,
    inject,
    provide,
    route,
)
from fastapi_fin.features import GuardDefinition, InterceptorDefinition

audit_log: list[str] = []
lifecycle_log: list[str] = []


class DashboardService:
    def status(self) -> str:
        return "ready"


def admin_only(subject: object) -> bool:
    return getattr(subject, "headers", {}).get("X-Role") == "admin"


async def audit(
    next_call: Callable[[tuple[object, ...], dict[str, object]], Awaitable[object]],
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> object:
    audit_log.append("request")
    return await next_call(args, kwargs)


def startup() -> None:
    lifecycle_log.append("started")


def shutdown() -> None:
    lifecycle_log.append("stopped")


SERVICE = inject(DashboardService)


def dashboard(service: DashboardService = SERVICE) -> dict[str, str]:
    return {"status": service.status()}


def build_app() -> FastAPI:
    audit_log.clear()
    lifecycle_log.clear()
    definition = ApplicationDefinition(
        routes=(
            route(
                "/admin/dashboard",
                dashboard,
                guards=(GuardDefinition(admin_only, name="admin-only"),),
            ),
        ),
        providers=(provide(DashboardService, scope=Scope.APPLICATION, eager=True),),
        interceptors=(InterceptorDefinition(audit, name="audit"),),
        lifecycle=LifecycleDefinition(startup=(startup,), shutdown=(shutdown,)),
    )
    return FastAPIAdapter.create_app(definition, title="Complete pipeline example")


if __name__ == "__main__":
    with TestClient(build_app()) as client:
        forbidden = client.get("/admin/dashboard")
        allowed = client.get("/admin/dashboard", headers={"X-Role": "admin"})

        assert forbidden.status_code == 403
        assert allowed.status_code == 200
        assert allowed.json() == {"status": "ready"}

    assert audit_log == ["request"]
    assert lifecycle_log == ["started", "stopped"]
    print("09_complete_pipeline: OK")
