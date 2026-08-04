import asyncio
from typing import Any, cast

from fastapi import FastAPI
import httpx
from pydantic import BaseModel
import pytest

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import (
    ApplicationDefinition,
    ApplicationRouter,
    LifecycleDefinition,
    Scope,
    inject,
    provide,
    route,
)
from fastapi_fin.errors import AdapterError
from fastapi_fin.features import GuardDefinition, InterceptorDefinition


def request(app, method: str, path: str, **kwargs: Any) -> httpx.Response:
    async def scenario() -> httpx.Response:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client,
        ):
            return await client.request(method, path, **kwargs)

    return asyncio.run(scenario())


def test_adapter_preserves_route_options_and_openapi() -> None:
    def read_item(item_id: int) -> dict[str, int]:
        return {"item_id": item_id}

    definition = ApplicationDefinition(
        routes=(
            route(
                "/items/{item_id}",
                read_item,
                methods="GET",
                tags=("items",),
                summary="Read item",
                operation_id="read-item",
            ),
        ),
    )
    app = FastAPIAdapter.create_app(definition, title="Contract")
    response = request(app, "GET", "/items/7")

    assert response.status_code == 200
    assert response.json() == {"item_id": 7}
    assert app.openapi()["paths"]["/items/{item_id}"]["get"]["operationId"] == "read-item"


def test_adapter_compiles_application_router_decorators() -> None:
    router = ApplicationRouter(prefix="/users", tags=("users",))

    @router.get("/{user_id}", operation_id="read-user")
    def read_user(user_id: int) -> dict[str, int]:
        return {"user_id": user_id}

    app = FastAPIAdapter.create_app(
        ApplicationDefinition(routes=router),
    )
    response = request(app, "GET", "/users/42")

    assert response.status_code == 200
    assert response.json() == {"user_id": 42}
    operation = app.openapi()["paths"]["/users/{user_id}"]["get"]
    assert operation["operationId"] == "read-user"
    assert operation["tags"] == ["users"]


def test_adapter_resolves_application_and_request_dependencies() -> None:
    class ApplicationService:
        pass

    class RequestService:
        pass

    application_service = inject(ApplicationService)
    request_service = inject(RequestService)

    def endpoint(
        application: ApplicationService = application_service,
        request_value: RequestService = request_service,
    ) -> dict[str, bool]:
        return {
            "application": isinstance(application, ApplicationService),
            "request": isinstance(request_value, RequestService),
        }

    definition = ApplicationDefinition(
        routes=(route("/dependencies", endpoint),),
        providers=(
            provide(ApplicationService, scope=Scope.APPLICATION),
            provide(RequestService, scope=Scope.REQUEST),
        ),
    )
    response = request(FastAPIAdapter.create_app(definition), "GET", "/dependencies")

    assert response.status_code == 200
    assert response.json() == {"application": True, "request": True}


def test_adapter_rejects_managed_definition_on_existing_app() -> None:
    class Service:
        pass

    with pytest.raises(AdapterError, match="create_app"):
        FastAPIAdapter.mount(
            FastAPI(),
            ApplicationDefinition(providers=(provide(Service),)),
        )


def test_adapter_rejects_invalid_existing_app_and_lifespan() -> None:
    with pytest.raises(AdapterError, match="FastAPI instance"):
        FastAPIAdapter.mount(cast("Any", object()), ApplicationDefinition())
    with pytest.raises(AdapterError, match="lifespan"):
        FastAPIAdapter.create_app(ApplicationDefinition(), lifespan=cast("Any", object()))


def test_adapter_runs_lifecycle_hooks_and_closes_runtime() -> None:
    events: list[str] = []
    definition = ApplicationDefinition(
        lifecycle=LifecycleDefinition(
            startup=(lambda: events.append("startup"),),
            shutdown=(lambda: events.append("shutdown"),),
        ),
    )
    app = FastAPIAdapter.create_app(definition)

    async def scenario() -> None:
        async with app.router.lifespan_context(app):
            assert events == ["startup"]
        assert events == ["startup", "shutdown"]

    asyncio.run(scenario())


def test_adapter_runs_runtime_cleanup_when_shutdown_hook_fails() -> None:
    closed: list[str] = []

    class Service:
        pass

    def fail_shutdown() -> None:
        raise RuntimeError("shutdown failed")

    definition = ApplicationDefinition(
        providers=(
            provide(
                Service,
                scope=Scope.APPLICATION,
                eager=True,
                disposer=lambda _value: closed.append("service"),
            ),
        ),
        lifecycle=LifecycleDefinition(shutdown=(fail_shutdown,)),
    )
    app = FastAPIAdapter.create_app(definition)

    async def scenario() -> None:
        with pytest.raises(ExceptionGroup, match="application shutdown failed"):
            async with app.router.lifespan_context(app):
                pass

    asyncio.run(scenario())
    assert closed == ["service"]


def test_adapter_translates_policies_and_all_route_options() -> None:
    events: list[str] = []

    class Response(BaseModel):
        status: str

    def is_admin(subject: object) -> bool:
        return getattr(subject, "headers", {}).get("X-Role") == "admin"

    async def audit(next_call, args, kwargs):
        events.append("audit")
        return await next_call(args, kwargs)

    def secure_endpoint(_fastapi_fin_request: str | None = None) -> Response:
        return Response(status="ok")

    definition = ApplicationDefinition(
        routes=(
            route(
                "/secure",
                secure_endpoint,
                methods="GET",
                name="secure",
                deprecated=True,
                response_model=Response,
                status_code=200,
                tags=("security",),
                summary="Secure endpoint",
                description="A protected endpoint",
                response_description="Success",
                operation_id="secure-endpoint",
                guards=(GuardDefinition(is_admin, name="admin"),),
            ),
        ),
        interceptors=(InterceptorDefinition(audit, name="audit"),),
    )
    app = FastAPIAdapter.create_app(definition)
    forbidden = request(app, "GET", "/secure")
    allowed = request(app, "GET", "/secure", headers={"X-Role": "admin"})

    assert forbidden.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json() == {"status": "ok"}
    assert events == ["audit"]
    operation = app.openapi()["paths"]["/secure"]["get"]
    assert operation["deprecated"] is True
    assert operation["operationId"] == "secure-endpoint"


def test_adapter_translates_request_resolution_errors_to_generic_500() -> None:
    class Service:
        pass

    service_marker = inject(Service)

    def endpoint(service: Service = service_marker) -> str:
        return service.__class__.__name__

    def failing_factory() -> Service:
        raise ValueError("secret details")

    app = FastAPIAdapter.create_app(
        ApplicationDefinition(
            routes=(route("/failure", endpoint),),
            providers=(provide(Service, failing_factory),),
        )
    )
    response = request(app, "GET", "/failure")

    assert response.status_code == 500
    assert response.json() == {"detail": "dependency resolution failed"}
