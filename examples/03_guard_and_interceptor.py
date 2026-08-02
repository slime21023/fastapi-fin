"""Compose a request guard and a cross-cutting interceptor."""

from collections.abc import Callable

from fastapi import Header
from fastapi.testclient import TestClient

from fastapi_fin import FastAPIAdapter, GuardRule, InterceptorSpec, controller, get, guard
from fastapi_fin.application import MetadataRegistry


def current_role(x_role: str | None = Header(default=None, alias="X-Role")) -> str | None:
    return x_role


audit_log: list[str] = []


def audit(
    next_call: Callable[[], object],
    _args: tuple[object, ...],
    _kwargs: dict[str, object],
) -> object:
    audit_log.append("request")
    return next_call()


admin_only = GuardRule(name="admin-only", predicate=lambda subject: subject == "admin")
audit_interceptor = InterceptorSpec(name="audit", handler=audit)


@controller(prefix="/admin")
class AdminController:
    @guard(admin_only)
    @get("/")
    def dashboard(self) -> dict[str, str]:
        return {"status": "ok"}


def build_app():
    registry = MetadataRegistry().register_controller(AdminController)
    return FastAPIAdapter.create_app(
        registry,
        guard_subject_provider=current_role,
        global_interceptors=(audit_interceptor,),
    )


if __name__ == "__main__":
    app = build_app()

    with TestClient(app) as client:
        forbidden = client.get("/admin/")
        allowed = client.get("/admin/", headers={"X-Role": "admin"})

    assert forbidden.status_code == 403
    assert allowed.status_code == 200
    assert audit_log == ["request"]
    print("03_guard_and_interceptor: OK")
