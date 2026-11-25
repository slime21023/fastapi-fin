"""ASGI applications served by the Uvicorn integration tests.

Importable by Uvicorn as ``uvicorn_apps:<name>`` with ``--app-dir tests/integration``.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Protocol, cast

from dishka import AsyncContainer, Provider, Scope, provide
from fastapi import FastAPI

from fastapi_fin import FastAPIIntegration, FinProxy, Inject, Module
from fastapi_fin.adapters import CONTAINER_STATE_KEY

# Resource lifecycle events, observable only by servers running inside the test process.
EVENTS: list[str] = []


class Greeting(Protocol):
    def message(self, name: str) -> str: ...


class DefaultGreeting:
    def message(self, name: str) -> str:
        return f"Hello, {name}!"


class Database:
    """An APP-scoped resource that records when it is opened and closed."""


class Providers(Provider):
    greeting = provide(DefaultGreeting, provides=Greeting, scope=Scope.APP)

    @provide(scope=Scope.APP)
    async def database(self) -> AsyncIterator[Database]:
        EVENTS.append("database-opened")
        yield Database()
        EVENTS.append("database-closed")


fin = FinProxy((Module("greetings", providers=(Providers(),), exports=(Greeting, Database)),))
integration = FastAPIIntegration(fin)


def add_hello_route(app: FastAPI) -> None:
    @app.get("/hello/{name}")
    def hello(name: str, greeting: Inject[Greeting], _database: Inject[Database]) -> dict[str, str]:
        return {"message": greeting.message(name)}


app = FastAPI(lifespan=integration.lifespan)
add_hello_route(app)


@asynccontextmanager
async def warm_up_lifespan(app: FastAPI) -> AsyncIterator[dict[str, object]]:
    async with integration.lifespan(app) as state:
        container = cast("AsyncContainer", state[CONTAINER_STATE_KEY])
        await container.get(Database)
        yield state


warmed_up_app = FastAPI(lifespan=warm_up_lifespan)
add_hello_route(warmed_up_app)


class Missing:
    """A contract that no module exports."""


misconfigured_app = FastAPI(lifespan=FastAPIIntegration(FinProxy()).lifespan)


@misconfigured_app.get("/missing")
def read_missing(_missing: Inject[Missing]) -> None:
    return None
