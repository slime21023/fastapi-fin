from typing import Any, cast

import pytest

from fastapi_fin.application import ApplicationRegistry, controller, get, module
from fastapi_fin.core import DeclarationError, GuardRule, HttpMethod, RegistrationError, Scope
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


def test_module_returns_new_registry_and_detects_route_conflicts() -> None:
    metadata = get_module_metadata(ApiModule)
    initial = ApplicationRegistry()
    registered = initial.module(metadata)

    assert initial.metadata.version == 0
    assert registered.metadata.version == 2
    assert len(registered.metadata.routes) == 2

    with pytest.raises(RegistrationError):
        registered.module(metadata)


def test_application_registry_composes_metadata_and_providers_immutably() -> None:
    initial = ApplicationRegistry()

    class Database:
        pass

    updated = initial.controller(UserController).provide(Database, scope=Scope.SINGLETON)

    assert initial.metadata.version == 0
    assert initial.providers.version == 0
    assert updated.metadata.version == 1
    assert updated.providers.version == 1
    assert updated.providers.find(Database) is not None


def test_registry_rejects_invalid_registration_inputs_early() -> None:
    registry = ApplicationRegistry()

    with pytest.raises(DeclarationError, match="@controller"):
        registry.controller(cast("Any", object()))
    with pytest.raises(DeclarationError, match="@module"):
        registry.module(cast("Any", None))
    with pytest.raises(RegistrationError, match="ControllerMetadata"):
        MetadataSnapshot().register(cast("Any", object()))
    with pytest.raises(RegistrationError, match="MetadataSnapshot"):
        ApplicationRegistry(metadata=cast("MetadataSnapshot", object()))
