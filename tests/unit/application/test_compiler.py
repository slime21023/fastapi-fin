from typing import TYPE_CHECKING, cast

from attrs import evolve
import pytest

from fastapi_fin.application import (
    CompiledApplication,
    MetadataRegistry,
    compile_application,
    controller,
    get,
)
from fastapi_fin.core import (
    DeclarationError,
    GuardRule,
    InterceptorSpec,
    RegistrationError,
)
from fastapi_fin.core.metadata import get_controller_metadata

if TYPE_CHECKING:
    from collections.abc import Iterable

    from fastapi_fin.application.compiler import CompiledRoute, EndpointResolver


def _passthrough(next_call, _args, _kwargs):
    return next_call()


@controller(prefix="/users")
class UserController:
    @get("/")
    def list_users(self) -> dict[str, str]:
        return {"status": "ok"}


def test_compile_application_builds_immutable_routes_from_registry_snapshot() -> None:
    registry = MetadataRegistry().register(get_controller_metadata(UserController))
    resolver_calls: list[str] = []

    def resolve(controller_metadata, route_metadata):
        resolver_calls.append(route_metadata.name)
        return getattr(controller_metadata.controller, route_metadata.endpoint.__name__)

    compiled = compile_application(registry, endpoint_resolver=resolve)

    assert compiled.registry_version == registry.snapshot.version == 1
    assert [route.metadata.path for route in compiled.routes] == ["/users/"]
    assert resolver_calls == ["list_users"]
    assert compiled.routes[0].endpoint is UserController.list_users
    attribute_name = "routes"
    with pytest.raises(AttributeError):
        setattr(compiled, attribute_name, ())


def test_compiler_composes_global_policies_before_route_policies() -> None:
    route_guard = GuardRule(name="route", predicate=lambda _subject: True)
    route_interceptor = InterceptorSpec(
        name="route",
        handler=_passthrough,
        order=20,
    )

    @controller(prefix="/composed")
    class ComposedController:
        @get("/")
        def value(self) -> str:
            return "ok"

    route_metadata = get_controller_metadata(ComposedController).routes[0]
    route_metadata = evolve(
        route_metadata,
        guards=(route_guard,),
        interceptors=(route_interceptor,),
    )
    controller_metadata = get_controller_metadata(ComposedController)
    controller_metadata = evolve(controller_metadata, routes=(route_metadata,))
    registry = MetadataRegistry().register(controller_metadata)
    global_guard = GuardRule(name="global", predicate=lambda _subject: True)
    global_interceptor = InterceptorSpec(
        name="global",
        handler=_passthrough,
        order=10,
    )

    compiled = compile_application(
        registry,
        endpoint_resolver=lambda _controller, route: route.endpoint,
        global_guards=(global_guard,),
        global_interceptors=(global_interceptor,),
    )

    route = compiled.routes[0].metadata
    assert [rule.name for rule in route.guards] == ["global", "route"]
    assert [item.name for item in route.interceptors] == ["global", "route"]


def test_compiler_rejects_invalid_resolver_and_policy_conflicts_early() -> None:
    registry = MetadataRegistry().register(get_controller_metadata(UserController))

    with pytest.raises(DeclarationError):
        compile_application(registry, endpoint_resolver=cast("EndpointResolver", object()))

    duplicate = InterceptorSpec(name="duplicate", handler=_passthrough)

    @controller(prefix="/duplicate")
    class DuplicateController:
        @get("/")
        def value(self) -> str:
            return "ok"

    route = get_controller_metadata(DuplicateController).routes[0]
    route = evolve(route, interceptors=(duplicate,))
    controller_metadata = get_controller_metadata(DuplicateController)
    controller_metadata = evolve(controller_metadata, routes=(route,))

    with pytest.raises(RegistrationError):
        compile_application(
            MetadataRegistry().register(controller_metadata),
            endpoint_resolver=lambda _controller, route: route.endpoint,
            global_interceptors=(duplicate,),
        )


def test_compiled_application_rejects_invalid_route_values() -> None:
    with pytest.raises(DeclarationError, match="compiled application routes must be iterable"):
        CompiledApplication(routes=cast("Iterable[CompiledRoute]", object()))

    with pytest.raises(DeclarationError, match="CompiledRoute instances"):
        CompiledApplication(routes=(cast("CompiledRoute", object()),))
