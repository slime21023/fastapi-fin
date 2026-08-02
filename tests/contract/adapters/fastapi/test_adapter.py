import asyncio
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
import pytest

from fastapi_fin import AdapterError, CachePolicy, guard, use_interceptor
from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import MetadataRegistry, controller, get, put
from fastapi_fin.core import (
    ApplicationStarted,
    ApplicationStopping,
    ContainerRuntime,
    ContainerSnapshot,
    EventDispatcher,
    GuardRule,
    InterceptorSpec,
    Lifecycle,
)
from fastapi_fin.core.metadata import collect_controller_metadata, get_controller_metadata


@controller(prefix="/users")
class UserController:
    @get("/{user_id}")
    def get_user(self, user_id: int) -> dict[str, int]:
        return {"user_id": user_id}


@controller(prefix="/method-contract")
class MethodContractController:
    @put("/")
    def update(self) -> dict[str, str]:
        return {"method": "put"}


class UserResponse(BaseModel):
    user_id: int


@controller(prefix="/documented")
class DocumentedController:
    @get(
        "/",
        response_model=UserResponse,
        status_code=201,
        tags=(" users ", "users"),
        summary=" Get user ",
        description=" Returns a user.",
        response_description=" User response ",
        operation_id="documented-user",
    )
    def value(self) -> dict[str, int]:
        return {"user_id": 7}


def test_adapter_creates_public_fastapi_route_and_preserves_openapi() -> None:
    registry = MetadataRegistry().register(get_controller_metadata(UserController))
    app = FastAPIAdapter.create_app(registry)

    with TestClient(app) as client:
        response = client.get("/users/42")

    assert response.status_code == 200
    assert response.json() == {"user_id": 42}
    assert "/users/{user_id}" in app.openapi()["paths"]

    invalid = client.get("/users/not-an-int")
    assert invalid.status_code == 422


def test_adapter_includes_routes_into_an_existing_fastapi_app() -> None:
    registry = MetadataRegistry().register(get_controller_metadata(UserController))
    app = FastAPI()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    assert FastAPIAdapter(app).include(registry) is app

    with TestClient(app) as client:
        health_response = client.get("/health")
        response = client.get("/users/42")

    assert health_response.status_code == 200
    assert health_response.json() == {"status": "ok"}
    assert response.status_code == 200
    assert response.json() == {"user_id": 42}


def test_adapter_rejects_include_when_runtime_lifecycle_would_be_skipped() -> None:
    runtime = ContainerRuntime(snapshot=ContainerSnapshot())
    adapter = FastAPIAdapter(FastAPI(), container_runtime=runtime)

    with pytest.raises(AdapterError, match=r"use FastAPIAdapter\.create_app"):
        adapter.include(MetadataRegistry())


def test_adapter_rejects_invalid_constructor_inputs_at_declaration_time() -> None:
    with pytest.raises(AdapterError, match="app"):
        FastAPIAdapter(cast("FastAPI", object()))
    with pytest.raises(AdapterError, match="global guards must be iterable"):
        FastAPIAdapter(
            FastAPI(),
            global_guards=cast("tuple[GuardRule, ...]", None),
        )
    with pytest.raises(AdapterError, match="global interceptors must be iterable"):
        FastAPIAdapter(
            FastAPI(),
            global_interceptors=cast("tuple[InterceptorSpec, ...]", None),
        )
    with pytest.raises(AdapterError, match="controller_factory"):
        FastAPIAdapter(
            FastAPI(),
            controller_factory=cast("Callable[[type[object]], object]", object()),
        )
    with pytest.raises(AdapterError, match="container_runtime"):
        FastAPIAdapter(
            FastAPI(),
            container_runtime=cast("ContainerRuntime", object()),
        )
    with pytest.raises(AdapterError, match="guard_subject_provider"):
        FastAPIAdapter(
            FastAPI(),
            guard_subject_provider=cast("Callable[..., object]", object()),
        )
    with pytest.raises(AdapterError, match="event_dispatcher"):
        FastAPIAdapter(
            FastAPI(),
            event_dispatcher=cast("EventDispatcher", object()),
        )


def test_adapter_rejects_invalid_lifespan_at_app_creation() -> None:
    with pytest.raises(AdapterError, match="lifespan must be callable"):
        FastAPIAdapter.create_app(
            MetadataRegistry(),
            lifespan=cast("Callable[[FastAPI], AbstractAsyncContextManager[None]]", object()),
        )


def test_adapter_mounts_http_method_convenience_decorator() -> None:
    registry = MetadataRegistry().register(get_controller_metadata(MethodContractController))
    app = FastAPIAdapter.create_app(registry)

    with TestClient(app) as client:
        response = client.put("/method-contract/")

    assert response.status_code == 200
    assert response.json() == {"method": "put"}
    assert "put" in app.openapi()["paths"]["/method-contract/"]


def test_adapter_preserves_route_options_and_pydantic_response_model() -> None:
    registry = MetadataRegistry().register(get_controller_metadata(DocumentedController))
    app = FastAPIAdapter.create_app(registry)

    with TestClient(app) as client:
        response = client.get("/documented/")

    assert response.status_code == 201
    assert response.json() == {"user_id": 7}
    operation = app.openapi()["paths"]["/documented/"]["get"]
    assert operation["tags"] == ["users"]
    assert operation["summary"] == "Get user"
    assert operation["description"] == "Returns a user."
    assert operation["operationId"] == "documented-user"
    assert operation["responses"]["201"]["description"] == "User response"
    assert operation["responses"]["201"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/UserResponse"
    )


class Service:
    value = "from-container"


service_runtime = ContainerRuntime(
    snapshot=ContainerSnapshot().bind(Service, Service),
)
service_dependency = FastAPIAdapter(
    FastAPI(),
    container_runtime=service_runtime,
).dependency(Service)
service_dependency_marker = Depends(service_dependency)


@controller(prefix="/protected")
class ProtectedController:
    @guard(GuardRule(name="admin-only", predicate=lambda subject: subject == "admin"))
    @get("/")
    def protected(self) -> dict[str, str]:
        return {"status": "ok"}


interceptor_calls: list[str] = []


def mark_interceptor(next_call, _args, _kwargs):
    interceptor_calls.append("called")
    return next_call()


@controller(prefix="/intercepted")
class InterceptedController:
    @use_interceptor(
        InterceptorSpec(
            name="marker",
            handler=mark_interceptor,
        )
    )
    @get("/")
    def value(self) -> dict[str, str]:
        return {"value": "ok"}


@controller(prefix="/translated")
class TranslatedController:
    @use_interceptor(
        InterceptorSpec(
            name="translate-error",
            handler=lambda next_call, _args, _kwargs: next_call(),
            error_handler=lambda error: {"error": str(error)},
        )
    )
    @get("/")
    def value(self) -> dict[str, str]:
        raise ValueError("domain failure")


cached_calls = 0


@controller(prefix="/cached")
class CachedController:
    @use_interceptor(
        InterceptorSpec(
            name="cache-result",
            handler=lambda next_call, _args, _kwargs: next_call(),
            cache=CachePolicy(),
        )
    )
    @get("/{value}")
    def value(self, value: int) -> dict[str, int]:
        global cached_calls
        cached_calls += 1
        return {"value": value}


@controller(prefix="/services")
class ServiceController:
    @get("/")
    def value(self, service: Service = service_dependency_marker) -> dict[str, str]:
        return {"value": service.value}


def test_adapter_translates_guards_and_interceptors() -> None:
    registry = MetadataRegistry()
    registry = registry.register(get_controller_metadata(ProtectedController))
    registry = registry.register(get_controller_metadata(InterceptedController))
    registry = registry.register(get_controller_metadata(TranslatedController))
    app = FastAPIAdapter.create_app(
        registry,
        guard_subject_provider=lambda: "member",
    )

    with TestClient(app) as client:
        forbidden = client.get("/protected/")
        intercepted = client.get("/intercepted/")
        translated = client.get("/translated/")

    assert forbidden.status_code == 403
    assert intercepted.json() == {"value": "ok"}
    assert translated.json() == {"error": "domain failure"}
    assert interceptor_calls == ["called"]


def test_adapter_caches_interceptor_results_per_route_arguments() -> None:
    global cached_calls
    cached_calls = 0
    registry = MetadataRegistry().register(get_controller_metadata(CachedController))
    app = FastAPIAdapter.create_app(registry)

    with TestClient(app) as client:
        first = client.get("/cached/7")
        second = client.get("/cached/7")
        different = client.get("/cached/8")

    assert first.json() == {"value": 7}
    assert second.json() == {"value": 7}
    assert different.json() == {"value": 8}
    assert cached_calls == 2


def test_adapter_applies_global_guard_to_every_route() -> None:
    registry = MetadataRegistry().register(get_controller_metadata(UserController))
    app = FastAPIAdapter.create_app(
        registry,
        global_guards=(
            GuardRule(name="global-admin", predicate=lambda subject: subject == "admin"),
        ),
        guard_subject_provider=lambda: "member",
    )

    with TestClient(app) as client:
        response = client.get("/users/42")

    assert response.status_code == 403


def test_adapter_translates_container_dependency() -> None:
    registry = MetadataRegistry().register(get_controller_metadata(ServiceController))
    app = FastAPIAdapter.create_app(registry)

    with TestClient(app) as client:
        response = client.get("/services/")

    assert response.status_code == 200
    assert response.json() == {"value": "from-container"}


def test_adapter_translates_resolution_errors_without_leaking_container_details() -> None:
    class MissingService:
        pass

    runtime = ContainerRuntime(snapshot=ContainerSnapshot())
    missing_dependency = Depends(
        FastAPIAdapter(FastAPI(), container_runtime=runtime).dependency(MissingService)
    )

    @controller(prefix="/missing-service")
    class MissingServiceController:
        @get("/")
        def value(self, _service: MissingService = missing_dependency) -> dict[str, str]:
            return {"status": "unreachable"}

    registry = MetadataRegistry().register(get_controller_metadata(MissingServiceController))
    app = FastAPIAdapter.create_app(registry, container_runtime=runtime)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/missing-service/")

    assert response.status_code == 500
    assert response.json() == {"detail": "dependency resolution failed"}
    assert "no service binding" not in response.text


def test_adapter_can_resolve_controller_from_container() -> None:
    runtime = ContainerRuntime(
        snapshot=ContainerSnapshot().bind(UserController, UserController),
    )
    registry = MetadataRegistry().register(get_controller_metadata(UserController))
    app = FastAPIAdapter.create_app(registry, container_runtime=runtime)

    with TestClient(app) as client:
        response = client.get("/users/42")

    assert response.status_code == 200
    assert response.json() == {"user_id": 42}


def test_adapter_keeps_instances_separate_for_repeated_controller_metadata() -> None:
    class ReusedController:
        def __init__(self) -> None:
            self.instance_number = 0

        @get("/")
        def value(self) -> dict[str, int]:
            return {"instance": self.instance_number}

    first_metadata = collect_controller_metadata(ReusedController, prefix="/first")
    second_metadata = collect_controller_metadata(ReusedController, prefix="/second")
    registry = MetadataRegistry().register(first_metadata).register(second_metadata)
    factory_calls = 0

    def factory(controller: type[object]) -> object:
        nonlocal factory_calls
        factory_calls += 1
        assert controller is ReusedController
        instance = ReusedController()
        instance.instance_number = factory_calls
        return instance

    app = FastAPIAdapter.create_app(registry, controller_factory=factory)

    with TestClient(app) as client:
        first = client.get("/first/")
        second = client.get("/second/")

    assert first.json() == {"instance": 1}
    assert second.json() == {"instance": 2}
    assert factory_calls == 2


def test_adapter_resolves_request_scoped_controller_per_request() -> None:
    dependency_calls = 0

    class RequestDependency:
        def __init__(self, sequence: int) -> None:
            self.sequence = sequence

    def build_dependency() -> RequestDependency:
        nonlocal dependency_calls
        dependency_calls += 1
        return RequestDependency(dependency_calls)

    @controller(prefix="/request-scoped")
    class RequestScopedController:
        def __init__(self, dependency: RequestDependency) -> None:
            self.dependency = dependency

        @get("/")
        def value(self) -> dict[str, int]:
            return {"sequence": self.dependency.sequence}

    runtime = ContainerRuntime(
        snapshot=(
            ContainerSnapshot()
            .bind(
                RequestDependency,
                build_dependency,
                lifecycle=Lifecycle.REQUEST,
            )
            .bind(
                RequestScopedController,
                RequestScopedController,
                lifecycle=Lifecycle.REQUEST,
            )
        )
    )
    registry = MetadataRegistry().register(get_controller_metadata(RequestScopedController))
    app = FastAPIAdapter.create_app(registry, container_runtime=runtime)

    with TestClient(app) as client:
        first = client.get("/request-scoped/")
        second = client.get("/request-scoped/")

    assert first.json() == {"sequence": 1}
    assert second.json() == {"sequence": 2}
    assert dependency_calls == 2
    route_schema = app.openapi()["paths"]["/request-scoped/"]["get"]
    assert "_fastapi_fin_controller" not in str(route_schema)


def test_adapter_initializes_non_lazy_singletons_during_startup() -> None:
    calls: list[str] = []

    async def build_service() -> object:
        calls.append("initialized")
        return object()

    runtime = ContainerRuntime(
        snapshot=ContainerSnapshot().bind(
            "eager-service",
            build_service,
            lifecycle=Lifecycle.SINGLETON,
            lazy=False,
        )
    )
    app = FastAPIAdapter.create_app(MetadataRegistry(), container_runtime=runtime)

    assert calls == []
    with TestClient(app):
        assert calls == ["initialized"]

    assert asyncio.run(runtime.resolve_async("eager-service")) is asyncio.run(
        runtime.resolve_async("eager-service")
    )


def test_adapter_closes_request_resources_after_each_request() -> None:
    events: list[str] = []

    class RequestResource:
        def close(self) -> None:
            events.append("closed")

    def build_resource() -> RequestResource:
        return RequestResource()

    runtime = ContainerRuntime(
        snapshot=ContainerSnapshot().bind(
            RequestResource,
            build_resource,
            lifecycle=Lifecycle.REQUEST,
        )
    )
    dependency_adapter = FastAPIAdapter(FastAPI(), container_runtime=runtime)
    resource_dependency = Depends(dependency_adapter.dependency(RequestResource))

    @controller(prefix="/request-cleanup")
    class RequestCleanupController:
        @get("/")
        def value(self, _resource: RequestResource = resource_dependency) -> dict[str, str]:
            return {"status": "ok"}

    registry = MetadataRegistry().register(get_controller_metadata(RequestCleanupController))
    app = FastAPIAdapter.create_app(registry, container_runtime=runtime)

    with TestClient(app) as client:
        assert client.get("/request-cleanup/").json() == {"status": "ok"}
        assert events == ["closed"]
        assert client.get("/request-cleanup/").json() == {"status": "ok"}
        assert events == ["closed", "closed"]


def test_adapter_closes_singleton_resources_on_shutdown() -> None:
    events: list[str] = []

    class SingletonResource:
        def close(self) -> None:
            events.append("closed")

    runtime = ContainerRuntime(
        snapshot=ContainerSnapshot().bind(
            SingletonResource,
            SingletonResource,
            lifecycle=Lifecycle.SINGLETON,
        )
    )
    runtime.resolve(SingletonResource)
    app = FastAPIAdapter.create_app(MetadataRegistry(), container_runtime=runtime)

    with TestClient(app):
        assert events == []

    assert events == ["closed"]


def test_adapter_initializes_runtime_inside_user_lifespan_before_started() -> None:
    lifecycle_events: list[str] = []

    async def build_service() -> object:
        lifecycle_events.append("container-startup")
        return object()

    @asynccontextmanager
    async def user_lifespan(_app):
        lifecycle_events.append("user-startup")
        yield
        lifecycle_events.append("user-shutdown")

    dispatcher = (
        EventDispatcher()
        .subscribe(
            ApplicationStarted,
            lambda _event: lifecycle_events.append("started"),
        )
        .subscribe(
            ApplicationStopping,
            lambda _event: lifecycle_events.append("stopping"),
        )
    )
    runtime = ContainerRuntime(
        snapshot=ContainerSnapshot().bind(
            "eager-service",
            build_service,
            lifecycle=Lifecycle.SINGLETON,
            lazy=False,
        )
    )
    app = FastAPIAdapter.create_app(
        MetadataRegistry(),
        container_runtime=runtime,
        event_dispatcher=dispatcher,
        lifespan=user_lifespan,
    )

    with TestClient(app):
        assert lifecycle_events == ["user-startup", "container-startup", "started"]

    assert lifecycle_events == [
        "user-startup",
        "container-startup",
        "started",
        "user-shutdown",
        "stopping",
    ]


def test_adapter_composes_lifespan_and_dispatches_application_events() -> None:
    lifecycle_events: list[str] = []

    def record_started(_event: ApplicationStarted) -> None:
        lifecycle_events.append("started")

    def record_stopping(_event: ApplicationStopping) -> None:
        lifecycle_events.append("stopping")

    dispatcher = (
        EventDispatcher()
        .subscribe(ApplicationStarted, record_started)
        .subscribe(ApplicationStopping, record_stopping)
    )
    registry = MetadataRegistry().register(get_controller_metadata(UserController))
    app = FastAPIAdapter.create_app(registry, event_dispatcher=dispatcher)

    with TestClient(app):
        assert lifecycle_events == ["started"]

    assert lifecycle_events == ["started", "stopping"]


def test_adapter_dispatches_lifecycle_events_around_user_lifespan() -> None:
    lifecycle_events: list[str] = []

    @asynccontextmanager
    async def user_lifespan(_app):
        lifecycle_events.append("user-startup")
        yield
        lifecycle_events.append("user-shutdown")

    dispatcher = (
        EventDispatcher()
        .subscribe(ApplicationStarted, lambda _event: lifecycle_events.append("started"))
        .subscribe(ApplicationStopping, lambda _event: lifecycle_events.append("stopping"))
    )
    registry = MetadataRegistry().register(get_controller_metadata(UserController))
    app = FastAPIAdapter.create_app(
        registry,
        event_dispatcher=dispatcher,
        lifespan=user_lifespan,
    )

    with TestClient(app):
        assert lifecycle_events == ["user-startup", "started"]

    assert lifecycle_events == ["user-startup", "started", "user-shutdown", "stopping"]
