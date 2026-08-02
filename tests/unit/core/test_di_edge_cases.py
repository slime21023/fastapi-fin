from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from time import sleep
from typing import Annotated

import pytest

from fastapi_fin.core import (
    ContainerRuntime,
    ContainerSnapshot,
    DeclarationError,
    Lifecycle,
    ResolutionError,
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


def test_container_resolves_future_annotations_and_tracks_snapshot_versions() -> None:
    initial = ContainerSnapshot()
    snapshot = (
        initial.bind(" database ", FutureDatabase)
        .bind(FutureDatabase, FutureDatabase)
        .bind(FutureService, FutureService)
        .replace("database", FutureDatabase)
    )

    resolved = ContainerRuntime(snapshot=snapshot).resolve(FutureService)

    assert initial.version == 0
    assert snapshot.version == 4
    assert isinstance(resolved, FutureService)
    assert isinstance(resolved.database, FutureDatabase)


def test_container_rejects_invalid_tokens_and_sync_async_resolution() -> None:
    with pytest.raises(DeclarationError):
        ContainerSnapshot().bind("  ", FutureDatabase)

    async def build() -> FutureDatabase:
        return FutureDatabase()

    runtime = ContainerRuntime(snapshot=ContainerSnapshot().bind("db", build))
    with pytest.raises(ResolutionError, match="resolve_async"):
        runtime.resolve("db")

    assert isinstance(asyncio.run(runtime.resolve_async("db")), FutureDatabase)


def test_container_supports_explicit_string_tokens_in_annotations() -> None:
    def build_service(database: FutureDatabase) -> FutureDatabase:
        return database

    build_service.__annotations__["database"] = "database"

    runtime = ContainerRuntime(
        snapshot=ContainerSnapshot()
        .bind("database", FutureDatabase)
        .bind("service", build_service),
    )

    assert isinstance(runtime.resolve("service"), FutureDatabase)


def test_container_unwraps_annotated_service_tokens() -> None:
    class AnnotatedService:
        def __init__(self, database: Annotated[FutureDatabase, "inject:database"]) -> None:
            self.database = database

    runtime = ContainerRuntime(
        snapshot=ContainerSnapshot()
        .bind(FutureDatabase, FutureDatabase)
        .bind(AnnotatedService, AnnotatedService),
    )

    resolved = runtime.resolve(AnnotatedService)

    assert isinstance(resolved, AnnotatedService)
    assert isinstance(resolved.database, FutureDatabase)


def test_container_unwraps_annotated_string_tokens_with_future_annotations() -> None:
    def build_service(database: FutureDatabase) -> FutureDatabase:
        return database

    build_service.__annotations__["database"] = 'Annotated["database", "inject:database"]'

    runtime = ContainerRuntime(
        snapshot=ContainerSnapshot()
        .bind("database", FutureDatabase)
        .bind("service", build_service),
    )

    assert isinstance(runtime.resolve("service"), FutureDatabase)


def test_container_initializes_non_lazy_singletons_on_explicit_request() -> None:
    calls = 0

    def build_database() -> FutureDatabase:
        nonlocal calls
        calls += 1
        return FutureDatabase()

    runtime = ContainerRuntime(
        snapshot=ContainerSnapshot().bind(
            "database",
            build_database,
            lifecycle="singleton",
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
        snapshot=ContainerSnapshot().bind(
            "database",
            build_database,
            lifecycle=Lifecycle.SINGLETON,
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
        snapshot=ContainerSnapshot().bind(
            "database",
            build_database,
            lifecycle=Lifecycle.SINGLETON,
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
        snapshot=ContainerSnapshot().bind(
            "database",
            build_database,
            lifecycle=Lifecycle.SINGLETON,
        ),
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        values = list(executor.map(runtime.resolve, ("database",) * 32))

    assert all(value is values[0] for value in values)
    assert calls == 1


def test_container_rejects_singleton_dependency_on_request_scope() -> None:
    runtime = ContainerRuntime(
        snapshot=(
            ContainerSnapshot()
            .bind(RequestState, RequestState, lifecycle=Lifecycle.REQUEST)
            .bind(SingletonState, SingletonState, lifecycle=Lifecycle.SINGLETON)
        )
    )

    with pytest.raises(ResolutionError, match="singleton services cannot depend"):
        runtime.resolve(SingletonState)
    with pytest.raises(ResolutionError, match="singleton services cannot depend"):
        asyncio.run(runtime.resolve_async(SingletonState))
