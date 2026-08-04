from typing import cast

import pytest

from fastapi_fin.application import (
    ApplicationDefinition,
    ApplicationRouter,
    assemble,
)
from fastapi_fin.errors import AssemblyError, DefinitionError
from fastapi_fin.features import GuardDefinition, InterceptorDefinition


def test_router_decorators_build_prefixed_immutable_route_snapshots() -> None:
    router = ApplicationRouter(prefix=" /users/ ", tags=("users",))

    @router.get("/{user_id}", summary="Read user")
    def read_user(user_id: int) -> dict[str, int]:
        return {"user_id": user_id}

    first_snapshot = router.snapshot()

    @router.post("/", status_code=201)
    def create_user() -> dict[str, str]:
        return {"status": "created"}

    assert first_snapshot == (first_snapshot[0],)
    assert first_snapshot[0].endpoint is read_user
    assert first_snapshot[0].path == "/users/{user_id}"
    assert first_snapshot[0].tags == ("users",)
    assert first_snapshot[0].summary == "Read user"
    assert router.routes[1].path == "/users/"
    assert router.routes[1].status_code == 201


def test_router_composition_merges_prefix_tags_and_policies() -> None:
    child_guard = GuardDefinition(lambda _subject: True, name="child")
    parent_guard = GuardDefinition(lambda _subject: True, name="parent")
    child_interceptor = InterceptorDefinition(
        lambda next_call, args, kwargs: next_call(args, kwargs)
    )
    parent_interceptor = InterceptorDefinition(
        lambda next_call, args, kwargs: next_call(args, kwargs)
    )

    child = ApplicationRouter(
        prefix="/users",
        tags=("users",),
        guards=(child_guard,),
        interceptors=(child_interceptor,),
    )

    @child.get("/")
    def list_users() -> list[str]:
        return []

    parent = ApplicationRouter(
        prefix="/api",
        tags=("api",),
        guards=(parent_guard,),
        interceptors=(parent_interceptor,),
    )
    parent.include_router(child, prefix="/v1", tags=("v1",))

    definition = parent.snapshot()[0]
    assert definition.path == "/api/v1/users/"
    assert definition.tags == ("api", "v1", "users")
    assert definition.guards == (parent_guard, child_guard)
    assert definition.interceptors == (parent_interceptor, child_interceptor)
    assert definition.endpoint is list_users


def test_router_sources_can_be_assembled_and_conflicts_are_global() -> None:
    first = ApplicationRouter()
    second = ApplicationRouter()

    @first.get("/health")
    def first_health() -> dict[str, str]:
        return {"status": "ok"}

    @second.get("/health")
    def second_health() -> dict[str, str]:
        return {"status": "ok"}

    with pytest.raises(AssemblyError, match="duplicate route"):
        assemble(
            ApplicationDefinition(routes=(first, second)),
        )


def test_router_rejects_invalid_declaration_values_immediately() -> None:
    with pytest.raises(DefinitionError, match="router prefix"):
        ApplicationRouter(prefix="/bad path")
    with pytest.raises(DefinitionError, match="router tags"):
        ApplicationRouter(tags="users")
    with pytest.raises(DefinitionError, match="route path"):
        ApplicationRouter().get("")(lambda: None)
    with pytest.raises(DefinitionError, match="included router"):
        ApplicationRouter().include_router(cast("ApplicationRouter", object()))


def test_router_supports_all_common_method_decorators() -> None:
    router = ApplicationRouter()

    @router.put("/put")
    def put_route() -> None:
        return None

    @router.patch("/patch")
    def patch_route() -> None:
        return None

    @router.delete("/delete")
    def delete_route() -> None:
        return None

    @router.options("/options")
    def options_route() -> None:
        return None

    @router.head("/head")
    def head_route() -> None:
        return None

    @router.trace("/trace")
    def trace_route() -> None:
        return None

    @router.connect("/connect")
    def connect_route() -> None:
        return None

    assert tuple(item.methods[0].value for item in router.routes) == (
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
        "TRACE",
        "CONNECT",
    )
