"""Compose a request guard and a framework-independent interceptor."""

from collections.abc import Awaitable, Callable

from fastapi.testclient import TestClient

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationDefinition, route
from fastapi_fin.features import GuardDefinition, InterceptorDefinition

audit_log: list[str] = []


def admin_only(subject: object) -> bool:
    return getattr(subject, "headers", {}).get("X-Role") == "admin"


async def audit(
    next_call: Callable[[tuple[object, ...], dict[str, object]], Awaitable[object]],
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> object:
    audit_log.append("request")
    return await next_call(args, kwargs)


def dashboard() -> dict[str, str]:
    return {"status": "ok"}


def build_app():
    definition = ApplicationDefinition(
        routes=(
            route(
                "/admin/",
                dashboard,
                guards=(GuardDefinition(admin_only, name="admin-only"),),
            ),
        ),
        interceptors=(InterceptorDefinition(audit, name="audit"),),
    )
    return FastAPIAdapter.create_app(definition)


if __name__ == "__main__":
    with TestClient(build_app()) as client:
        forbidden = client.get("/admin/")
        allowed = client.get("/admin/", headers={"X-Role": "admin"})

    assert forbidden.status_code == 403
    assert allowed.status_code == 200
    assert audit_log == ["request"]
    print("03_guard_and_interceptor: OK")
