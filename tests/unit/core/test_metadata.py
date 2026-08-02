from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Iterable

import pytest

from fastapi_fin.application import get
from fastapi_fin.core import (
    DeclarationError,
    InterceptorSpec,
    MetadataSnapshot,
    RegistrationError,
)
from fastapi_fin.core.metadata import (
    ControllerMetadata,
    ModuleMetadata,
    RouteMetadata,
    collect_controller_metadata,
)


class UserController:
    @get("/")
    def list_users(self) -> list[str]:
        return []


def test_controller_metadata_contains_prefixed_route() -> None:
    metadata = collect_controller_metadata(UserController, prefix="/users")

    assert metadata.routes[0].path == "/users/"
    assert metadata.routes[0].endpoint is UserController.list_users


def test_snapshot_register_returns_new_version_without_mutating_old_snapshot() -> None:
    metadata = collect_controller_metadata(UserController, prefix="/users")
    initial = MetadataSnapshot()

    updated = initial.register(metadata)

    assert initial.version == 0
    assert initial.controllers == ()
    assert updated.version == 1
    assert updated.controllers == (metadata,)


def test_snapshot_rejects_duplicate_method_and_path() -> None:
    metadata = collect_controller_metadata(UserController, prefix="/users")
    initial = MetadataSnapshot().register(metadata)

    with pytest.raises(RegistrationError, match="duplicate route"):
        initial.register(metadata)


def test_metadata_rejects_invalid_nested_values_at_construction() -> None:
    with pytest.raises(DeclarationError, match="RouteMetadata"):
        ControllerMetadata(
            controller=UserController,
            prefix="/users",
            routes=cast("Iterable[RouteMetadata]", (object(),)),
            name="users",
        )

    with pytest.raises(DeclarationError, match="InterceptorSpec"):
        RouteMetadata(
            path="/",
            methods="GET",
            endpoint=lambda: None,
            name="invalid-interceptor",
            interceptors=cast("Iterable[InterceptorSpec]", (object(),)),
        )

    interceptor = InterceptorSpec(
        name="valid",
        handler=lambda next_call, _args, _kwargs: next_call(),
    )
    valid_route = RouteMetadata(
        path="/",
        methods="GET",
        endpoint=lambda: None,
        name="valid-route",
        interceptors=(interceptor,),
    )
    valid_controller = ControllerMetadata(
        controller=UserController,
        prefix="/users",
        routes=(valid_route,),
        name="users",
    )
    with pytest.raises(DeclarationError, match="ModuleMetadata"):
        ModuleMetadata(
            name="invalid-module",
            modules=cast("Iterable[ModuleMetadata]", (object(),)),
        )
    with pytest.raises(DeclarationError, match="ControllerMetadata"):
        ModuleMetadata(
            name="invalid-controller",
            controllers=cast("Iterable[ControllerMetadata]", (object(),)),
        )
    assert valid_controller.routes == (valid_route,)
