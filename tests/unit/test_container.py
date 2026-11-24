import asyncio
from collections.abc import Iterator
from typing import Protocol

from dishka import Provider, Scope, provide
from dishka.exceptions import InvalidGraphError, NoFactoryError
import pytest

from fastapi_fin.container import build_container, open_container
from fastapi_fin.errors import AssemblyError
from fastapi_fin.modules import Application, Module


class UserDirectory(Protocol):
    def name(self) -> str: ...


class UserTable:
    def name(self) -> str:
        return "production"


class FakeDirectory:
    def name(self) -> str:
        return "test"


class OrderService:
    def __init__(self, directory: UserDirectory) -> None:
        self.directory = directory


class UserService(OrderService):
    pass


class Users(Provider):
    table = provide(UserTable, scope=Scope.APP, provides=UserDirectory)
    service = provide(UserService, scope=Scope.APP)


class Orders(Provider):
    service = provide(OrderService, scope=Scope.APP)


@pytest.mark.parametrize("override", [False, True])
def test_contract_resolution_across_components(override: bool) -> None:
    async def scenario() -> None:
        app = Application(
            (
                Module("users", (Users(),), exports=(UserDirectory, UserService)),
                Module("orders", (Orders(),), exports=(OrderService,), requires=(UserDirectory,)),
            )
        )
        fake = FakeDirectory()
        async with open_container(
            app.with_overrides({UserDirectory: fake}) if override else app
        ) as root:
            selected = await root.get(UserDirectory)
            assert selected.name() == ("test" if override else "production")
            assert (await root.get(OrderService)).directory is selected
            assert (await root.get(UserService)).directory is selected
            if override:
                assert selected is fake
            with pytest.raises(NoFactoryError):
                await root.get(UserTable)

    asyncio.run(scenario())


def test_internal_factory_cannot_be_used_implicitly_by_another_module() -> None:
    class Other(Provider):
        @provide(scope=Scope.APP)
        def get_table_name(self, table: UserTable) -> str:
            return table.name()

    user_provider = Provider(scope=Scope.APP)
    user_provider.provide(UserTable)
    with pytest.raises(AssemblyError, match="dependency graph is invalid") as error:
        build_container(
            Application((Module("users", (user_provider,)), Module("other", (Other(),))))
        )
    assert isinstance(error.value.__cause__, InvalidGraphError)


def test_export_needs_a_provider() -> None:
    with pytest.raises(AssemblyError, match="dependency graph is invalid"):
        build_container(Application((Module("users", exports=(UserDirectory,)),)))


def test_requires_can_be_supplied_as_scope_context() -> None:
    class Clock:
        pass

    class Current(Provider):
        @provide(scope=Scope.REQUEST)
        def clock_id(self, clock: Clock) -> int:
            return id(clock)

    app = Application((Module("current", (Current(),), exports=(int,), requires=(Clock,)),))
    with pytest.raises(AssemblyError, match=r"'current' requires .*Clock"):
        build_container(app)

    async def scenario() -> None:
        async with open_container(app, context={Clock: Scope.REQUEST}) as root:
            clock = Clock()
            async with root(context={Clock: clock}) as request:
                assert await request.get(int) == id(clock)

    asyncio.run(scenario())


def test_finalizes_each_scope_in_order() -> None:
    events: list[str] = []

    class Resources(Provider):
        @provide(scope=Scope.APP)
        def pool(self) -> Iterator[int]:
            try:
                yield 42
            finally:
                events.append("app")

        @provide(scope=Scope.REQUEST)
        def session(self, pool: int) -> Iterator[str]:
            try:
                yield str(pool)
            finally:
                events.append("request")

    async def scenario() -> None:
        app = Application((Module("resources", (Resources(),), exports=(str,)),))
        async with open_container(app) as root:
            async with root() as request:
                assert await request.get(str) == "42"
            assert events == ["request"]
        assert events == ["request", "app"]

    asyncio.run(scenario())
