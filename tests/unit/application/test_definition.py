from typing import Any, cast

import pytest

from fastapi_fin.application import (
    ApplicationDefinition,
    HttpMethod,
    LifecycleDefinition,
    Scope,
    assemble,
    inject,
    provide,
    route,
)
from fastapi_fin.errors import AssemblyError, DefinitionError


def test_route_definition_normalizes_path_and_methods() -> None:
    def endpoint() -> dict[str, str]:
        return {"status": "ok"}

    definition = route(" users ", endpoint, methods=("get", HttpMethod.POST, "GET"))

    assert definition.path == "/users"
    assert definition.methods == (HttpMethod.GET, HttpMethod.POST)


def test_definitions_are_immutable_after_normalization() -> None:
    definition = route(" /health ", lambda: None, tags=["system"])

    assert definition.path == "/health"
    assert definition.tags == ("system",)
    with pytest.raises(AttributeError):
        setattr(definition, "path", "/changed")  # noqa: B010


def test_assembly_orders_providers_by_declared_dependencies() -> None:
    class Database:
        pass

    class Service:
        pass

    definition = ApplicationDefinition(
        providers=(
            provide(Service, dependencies=(Database,)),
            provide(Database, scope=Scope.APPLICATION),
        ),
    )

    model = assemble(definition)

    assert model.provider_order == (Database, Service)
    assert model.find_provider(Database) is not None


def test_assembly_rejects_duplicate_routes_and_provider_cycles() -> None:
    def endpoint() -> None:
        return None

    duplicate = ApplicationDefinition(
        routes=(route("/health", endpoint), route("/health", endpoint)),
    )
    with pytest.raises(AssemblyError, match="duplicate route"):
        assemble(duplicate)

    class First:
        pass

    class Second:
        pass

    cyclic = ApplicationDefinition(
        providers=(
            provide(First, dependencies=(Second,)),
            provide(Second, dependencies=(First,)),
        ),
    )
    with pytest.raises(AssemblyError, match="circular"):
        assemble(cyclic)


def test_assembly_rejects_missing_injection_and_invalid_scope_dependency() -> None:
    class Missing:
        pass

    missing_service = inject(Missing)

    def endpoint(service: Missing = missing_service) -> object:
        return service

    with pytest.raises(AssemblyError, match="missing token"):
        assemble(ApplicationDefinition(routes=(route("/", endpoint),)))

    class RequestService:
        pass

    class ApplicationService:
        pass

    definition = ApplicationDefinition(
        providers=(
            provide(
                ApplicationService,
                dependencies=(RequestService,),
                scope=Scope.APPLICATION,
            ),
            provide(RequestService, scope=Scope.REQUEST),
        ),
    )
    with pytest.raises(AssemblyError, match="cannot depend"):
        assemble(definition)


def test_definition_rejects_invalid_route_values_at_creation() -> None:
    with pytest.raises(DefinitionError, match="route path"):
        route("/bad path", lambda: None)

    with pytest.raises(DefinitionError, match="status_code"):
        route("/health", lambda: None, status_code=700)
    with pytest.raises(DefinitionError, match="operation_id"):
        route("/health", lambda: None, methods=("GET", "POST"), operation_id="health")

    with pytest.raises(DefinitionError, match="methods must be iterable"):
        route("/health", lambda: None, methods=cast("Any", None))
    with pytest.raises(DefinitionError, match="tags"):
        route("/health", lambda: None, tags="health")


def test_definition_rejects_non_iterable_application_values() -> None:
    with pytest.raises(DefinitionError, match="routes must be iterable"):
        ApplicationDefinition(routes=cast("Any", None))
    with pytest.raises(DefinitionError, match="lifecycle startup hooks"):
        LifecycleDefinition(startup=cast("Any", None))
