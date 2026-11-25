"""Share a contract across two modules and inject the orders service into FastAPI."""

from typing import Protocol

from dishka import Provider, Scope, provide
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin import FastAPIIntegration, FinComposition, Inject, Module


class UserDirectory(Protocol):
    def name_for(self, user_id: int) -> str: ...


class InMemoryUserDirectory:
    def __init__(self) -> None:
        self._names = {1: "Ada"}

    def name_for(self, user_id: int) -> str:
        return self._names[user_id]


class OrderService:
    def __init__(self, users: UserDirectory) -> None:
        self._users = users

    def summary(self, order_id: int) -> dict[str, int | str]:
        user_id = {42: 1}[order_id]
        return {"order_id": order_id, "customer": self._users.name_for(user_id)}


class UsersProvider(Provider):
    directory = provide(InMemoryUserDirectory, provides=UserDirectory, scope=Scope.APP)


class OrdersProvider(Provider):
    service = provide(OrderService, scope=Scope.REQUEST)


def main() -> None:
    users = Module("users", providers=(UsersProvider(),), exports=(UserDirectory,))
    orders = Module(
        "orders",
        providers=(OrdersProvider(),),
        exports=(OrderService,),
        requires=(UserDirectory,),
    )
    app = FastAPI(lifespan=FastAPIIntegration(FinComposition(modules=(users, orders))).lifespan)

    @app.get("/orders/{order_id}")
    async def read_order(order_id: int, service: Inject[OrderService]) -> dict[str, int | str]:
        return service.summary(order_id)

    with TestClient(app) as client:
        response = client.get("/orders/42")
        assert response.status_code == 200
        assert response.json() == {"order_id": 42, "customer": "Ada"}

    print("01_modules_and_contracts: OK")


if __name__ == "__main__":
    main()
