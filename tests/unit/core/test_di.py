import asyncio

import pytest

from fastapi_fin.core import (
    ContainerRuntime,
    ProviderRegistry,
    RegistrationError,
    ResolutionContext,
    ResolutionError,
    Scope,
)


class Database:
    pass


class UserService:
    def __init__(self, database: Database) -> None:
        self.database = database


def test_provider_registry_provides_classes_and_builds_runtime() -> None:
    providers = (
        ProviderRegistry()
        .provide(Database, scope=Scope.SINGLETON)
        .provide(UserService, scope=Scope.REQUEST)
    )

    runtime = ContainerRuntime(providers=providers)
    first_context = ResolutionContext()
    second_context = ResolutionContext()

    first = runtime.resolve(UserService, first_context)
    other_request = runtime.resolve(UserService, second_context)

    assert len(providers.providers) == 2
    assert isinstance(first, UserService)
    assert isinstance(other_request, UserService)
    assert first is not other_request
    assert first.database is other_request.database


def test_provider_runtime_resolves_annotated_dependencies_and_request_scope() -> None:
    snapshot = (
        ProviderRegistry()
        .provide(Database, scope=Scope.SINGLETON)
        .provide(UserService, scope=Scope.REQUEST)
    )
    runtime = ContainerRuntime(providers=snapshot)
    first_context = ResolutionContext()
    second_context = ResolutionContext()

    first = runtime.resolve(UserService, first_context)
    same_request = runtime.resolve(UserService, first_context)
    other_request = runtime.resolve(UserService, second_context)

    assert isinstance(first, UserService)
    assert isinstance(other_request, UserService)
    assert first is same_request
    assert first is not other_request
    assert first.database is other_request.database


def test_provider_registry_is_immutable_and_rejects_duplicate_providers() -> None:
    initial = ProviderRegistry()
    updated = initial.provide("database", Database)

    assert initial.providers == ()
    assert len(updated.providers) == 1
    with pytest.raises(RegistrationError):
        updated.provide("database", Database)


def test_container_runtime_does_not_allow_provider_registry_replacement() -> None:
    runtime = ContainerRuntime(providers=ProviderRegistry())

    with pytest.raises(AttributeError):
        runtime.providers = ProviderRegistry().provide(Database)


def test_container_resolves_async_factory() -> None:
    async def build_database() -> Database:
        return Database()

    runtime = ContainerRuntime(
        providers=ProviderRegistry().provide("database", build_database),
    )

    resolved = asyncio.run(runtime.resolve_async("database"))

    assert isinstance(resolved, Database)


def test_resolution_context_closes_request_and_transient_resources_in_reverse_order() -> None:
    events: list[str] = []

    class RequestResource:
        def close(self) -> None:
            events.append("request")

    class TransientResource:
        def __init__(self, resource: RequestResource) -> None:
            self.resource = resource

        def close(self) -> None:
            events.append("transient")

    runtime = ContainerRuntime(
        providers=(
            ProviderRegistry()
            .provide(RequestResource, scope=Scope.REQUEST)
            .provide(TransientResource, scope=Scope.TRANSIENT)
        )
    )
    with ResolutionContext() as context:
        runtime.resolve(TransientResource, context)
    context.close()

    assert events == ["transient", "request"]
    assert context.closed is True
    assert context.values == {}


def test_resolution_context_supports_async_context_management() -> None:
    runtime = ContainerRuntime(
        providers=ProviderRegistry().provide("database", Database),
    )

    async def resolve_in_context() -> bool:
        async with ResolutionContext() as context:
            assert isinstance(await runtime.resolve_async("database", context), Database)
        return context.closed

    assert asyncio.run(resolve_in_context()) is True


def test_sync_context_cleanup_preserves_async_resources_for_async_retry() -> None:
    events: list[str] = []

    class AsyncResource:
        async def aclose(self) -> None:
            events.append("closed")

    resource = AsyncResource()
    context = ResolutionContext()
    context.track(resource)

    with pytest.raises(ResolutionError, match="close_async"):
        context.close()

    assert context.closed is False
    asyncio.run(context.close_async())
    assert events == ["closed"]


def test_runtime_sync_cleanup_preserves_async_singletons_for_async_retry() -> None:
    events: list[str] = []

    class AsyncResource:
        async def aclose(self) -> None:
            events.append("closed")

    runtime = ContainerRuntime(
        providers=ProviderRegistry().provide(
            AsyncResource,
            scope=Scope.SINGLETON,
        ),
    )
    resource = runtime.resolve(AsyncResource)

    with pytest.raises(ResolutionError, match="close_async"):
        runtime.close()

    assert runtime.resolve(AsyncResource) is resource
    asyncio.run(runtime.close_async())
    assert events == ["closed"]


def test_container_runtime_closes_async_singletons_once() -> None:
    events: list[str] = []

    class AsyncResource:
        async def aclose(self) -> None:
            events.append("closed")

    runtime = ContainerRuntime(
        providers=ProviderRegistry().provide(
            AsyncResource,
            scope=Scope.SINGLETON,
        )
    )
    runtime.resolve(AsyncResource)

    asyncio.run(runtime.close_async())
    asyncio.run(runtime.close_async())

    assert events == ["closed"]
