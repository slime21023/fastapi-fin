"""Show where invalid module graphs and route injections are rejected."""

from collections.abc import Iterator
from contextlib import contextmanager

from dishka import Provider, Scope, provide
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin import (
    Application,
    AssemblyError,
    FastAPIIntegration,
    Inject,
    Module,
    build_container,
)


class UserTable:
    def count(self) -> int:
        return 1


class OrderService:
    def __init__(self, users: UserTable) -> None:
        self.users = users


class UsersProvider(Provider):
    table = provide(UserTable, scope=Scope.APP)


class OrdersProvider(Provider):
    service = provide(OrderService, scope=Scope.APP)


@contextmanager
def expect_assembly_error(*messages: str) -> Iterator[None]:
    try:
        yield
    except AssemblyError as error:
        detail = str(error)
    else:
        raise AssertionError("Expected AssemblyError")
    assert all(message in detail for message in messages), detail


def main() -> None:
    with expect_assembly_error("is exported by modules"):
        Application(
            modules=(Module("users", exports=(UserTable,)), Module("admin", exports=(UserTable,)))
        )

    with expect_assembly_error("neither exported by a module nor provided as context"):
        build_container(Application(modules=(Module("orders", requires=(UserTable,)),)))

    users = Module("users", providers=(UsersProvider(),))  # UserTable stays private.
    orders = Module("orders", providers=(OrdersProvider(),), exports=(OrderService,))
    with expect_assembly_error("dependency graph is invalid:", "UserTable"):
        build_container(Application(modules=(users, orders)))

    app = FastAPI(lifespan=FastAPIIntegration(Application(modules=(users,))).lifespan)

    @app.get("/users/count")
    async def count_users(table: Inject[UserTable]) -> dict[str, int]:
        return {"count": table.count()}

    with expect_assembly_error("which is not an exported contract"), TestClient(app):
        pass  # The route is rejected during startup, before any request is served.

    print("05_validation_failures: OK")


if __name__ == "__main__":
    main()
