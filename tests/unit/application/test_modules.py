from typing import Any, cast

import pytest

from fastapi_fin.application import MetadataRegistry, controller, get, module
from fastapi_fin.core import GuardRule, HttpMethod, RegistrationError
from fastapi_fin.core.metadata import MetadataSnapshot, get_module_metadata


def _allow(name: str) -> GuardRule:
    return GuardRule(name=name, predicate=lambda _subject: True)


@controller(prefix="/users")
class UserController:
    @get("/")
    def list_users(self) -> list[str]:
        return []


@controller(prefix="/health")
class HealthController:
    @get("/")
    def check(self) -> str:
        return "ok"


@module(
    name="users",
    prefix="/v1",
    controllers=(UserController,),
    guards=(_allow("module"),),
)
class UserModule:
    pass


@module(name="api", prefix="/api", modules=(UserModule,), controllers=(HealthController,))
class ApiModule:
    pass


def test_nested_module_composition_is_prefixed_and_policy_ordered() -> None:
    metadata = get_module_metadata(ApiModule)

    controllers = metadata.flatten_controllers()

    assert [route.path for controller in controllers for route in controller.routes] == [
        "/api/health/",
        "/api/v1/users/",
    ]
    assert controllers[1].routes[0].guards[0].name == "module"
    assert controllers[1].routes[0].methods == (HttpMethod.GET,)


def test_register_module_returns_new_registry_and_detects_route_conflicts() -> None:
    metadata = get_module_metadata(ApiModule)
    initial = MetadataRegistry()
    registered = initial.register_module(metadata)

    assert initial.snapshot.version == 0
    assert registered.snapshot.version == 2
    assert len(registered.snapshot.routes) == 2

    with pytest.raises(RegistrationError):
        registered.register_module(metadata)


def test_registry_rejects_invalid_registration_inputs_early() -> None:
    registry = MetadataRegistry()

    with pytest.raises(RegistrationError, match="ControllerMetadata"):
        registry.register(cast("Any", object()))
    with pytest.raises(RegistrationError, match="iterable"):
        registry.register_many(cast("Any", None))
    with pytest.raises(RegistrationError, match="ControllerMetadata"):
        MetadataSnapshot().register(cast("Any", object()))
    with pytest.raises(RegistrationError, match="MetadataSnapshot"):
        MetadataRegistry(snapshot=cast("MetadataSnapshot", object()))
