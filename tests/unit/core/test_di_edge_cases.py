from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from time import sleep
from typing import Annotated

import pytest

from fastapi_fin.core import (
    ContainerRuntime,
    DeclarationError,
    ProviderRegistry,
    ResolutionError,
    Scope,
)


class FutureDatabase:
    pass


class FutureService:
    def __init__(self, database: FutureDatabase) -> None:
        self.database = database


class RequestState:
    pass


class SingletonState:
    def __init__(self, state: RequestState) -> None:
        self.state = state


def test_provider_runtime_resolves_future_annotations_and_tracks_versions() -> None:
    initial = ProviderRegistry()
    snapshot = (
        initial.provide(" database ", FutureDatabase)
        .provide(FutureDatabase)
        .provide(FutureService)
        .replace("database", FutureDatabase)
    )

    resolved = ContainerRuntime(providers=snapshot).resolve(FutureService)

    assert initial.version == 0
    assert snapshot.version == 4
    assert isinstance(resolved, FutureService)
    assert isinstance(resolved.database, FutureDatabase)


def test_container_rejects_invalid_tokens_and_sync_async_resolution() -> None:
    with pytest.raises(DeclarationError):
        ProviderRegistry().provide("  ", FutureDatabase)

    async def build() -> FutureDatabase:
        return FutureDatabase()

    runtime = ContainerRuntime(providers=ProviderRegistry().provide("db", build))
    with pytest.raises(ResolutionError, match="resolve_async"):
        runtime.resolve("db")

    assert isinstance(asyncio.run(runtime.resolve_async("db")), FutureDatabase)


def test_container_supports_explicit_string_tokens_in_annotations() -> None:
    def build_service(database: FutureDatabase) -> FutureDatabase:
        return database

    build_service.__annotations__["database"] = "database"

    runtime = ContainerRuntime(
        providers=ProviderRegistry()
        .provide("database", FutureDatabase)
        .provide("service", build_service),
    )

    assert isinstance(runtime.resolve("service"), FutureDatabase)


def test_container_unwraps_annotated_service_tokens() -> None:
    class AnnotatedService:
        def __init__(self, database: Annotated[FutureDatabase, "inject:database"]) -> None:
            self.database = database

    runtime = ContainerRuntime(
        providers=ProviderRegistry().provide(FutureDatabase).provide(AnnotatedService),
    )

    resolved = runtime.resolve(AnnotatedService)

    assert isinstance(resolved, AnnotatedService)
    assert isinstance(resolved.database, FutureDatabase)


def test_container_unwraps_annotated_string_tokens_with_future_annotations() -> None:
    def build_service(database: FutureDatabase) -> FutureDatabase:
        return database

    build_service.__annotations__["database"] = 'Annotated["database", "inject:database"]'

    runtime = ContainerRuntime(
        providers=ProviderRegistry()
        .provide("database", FutureDatabase)
        .provide("service", build_service),
    )

    assert isinstance(runtime.resolve("service"), FutureDatabase)


def test_container_initializes_non_lazy_singletons_on_explicit_request() -> None:
    calls = 0

    def build_database() -> FutureDatabase:
        nonlocal calls
        calls += 1
        return FutureDatabase()

    runtime = ContainerRuntime(
        providers=ProviderRegistry().provide(
            "database",
            build_database,
            scope="singleton",
            lazy=False,
        )
    )

    assert calls == 0
    runtime.initialize()
    assert calls == 1
    assert runtime.resolve("database") is runtime.resolve("database")


def test_container_initializes_async_non_lazy_singletons() -> None:
    calls = 0

    async def build_database() -> FutureDatabase:
        nonlocal calls
        calls += 1
        return FutureDatabase()

    runtime = ContainerRuntime(
        providers=ProviderRegistry().provide(
            "database",
            build_database,
            scope=Scope.SINGLETON,
            lazy=False,
        )
    )

    asyncio.run(runtime.initialize_async())

    assert calls == 1
    assert runtime.resolve("database") is runtime.resolve("database")


def test_container_deduplicates_concurrent_async_singleton_resolution() -> None:
    calls = 0

    async def build_database() -> FutureDatabase:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return FutureDatabase()

    runtime = ContainerRuntime(
        providers=ProviderRegistry().provide(
            "database",
            build_database,
            scope=Scope.SINGLETON,
        ),
    )

    async def resolve_concurrently() -> tuple[object, object]:
        return await asyncio.gather(
            runtime.resolve_async("database"),
            runtime.resolve_async("database"),
        )

    first, second = asyncio.run(resolve_concurrently())

    assert first is second
    assert calls == 1


def test_container_deduplicates_concurrent_sync_singleton_resolution() -> None:
    calls = 0

    def build_database() -> FutureDatabase:
        nonlocal calls
        calls += 1
        sleep(0.01)
        return FutureDatabase()

    runtime = ContainerRuntime(
        providers=ProviderRegistry().provide(
            "database",
            build_database,
            scope=Scope.SINGLETON,
        ),
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        values = list(executor.map(runtime.resolve, ("database",) * 32))

    assert all(value is values[0] for value in values)
    assert calls == 1


def test_container_deduplicates_sync_and_async_singleton_resolution() -> None:
    calls = 0
    started = Event()

    def build_database() -> FutureDatabase:
        nonlocal calls
        calls += 1
        started.set()
        sleep(0.05)
        return FutureDatabase()

    runtime = ContainerRuntime(
        providers=ProviderRegistry().provide(
            "database",
            build_database,
            scope=Scope.SINGLETON,
        ),
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        sync_future = executor.submit(runtime.resolve, "database")
        assert started.wait(timeout=1)
        async_value = asyncio.run(runtime.resolve_async("database"))
        sync_value = sync_future.result()

    assert async_value is sync_value
    assert calls == 1


def test_container_rejects_singleton_dependency_on_request_scope() -> None:
    runtime = ContainerRuntime(
        providers=(
            ProviderRegistry()
            .provide(RequestState, scope=Scope.REQUEST)
            .provide(SingletonState, scope=Scope.SINGLETON)
        )
    )

    with pytest.raises(ResolutionError, match="singleton services cannot depend"):
        runtime.resolve(SingletonState)
    with pytest.raises(ResolutionError, match="singleton services cannot depend"):
        asyncio.run(runtime.resolve_async(SingletonState))
