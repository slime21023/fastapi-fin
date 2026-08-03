"""Show application/request scopes and deterministic disposer ordering."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationDefinition, Scope, inject, provide, route

events: list[str] = []
session_number = 0


class ConnectionPool:
    pass


class RequestSession:
    def __init__(self, pool: ConnectionPool, number: int) -> None:
        self.pool = pool
        self.number = number


def create_pool() -> ConnectionPool:
    events.append("pool-created")
    return ConnectionPool()


def close_pool(_pool: object) -> None:
    events.append("pool-closed")


def create_session(pool: ConnectionPool) -> RequestSession:
    global session_number
    session_number += 1
    session = RequestSession(pool, session_number)
    events.append(f"session-created-{session.number}")
    return session


async def close_session(value: object) -> None:
    assert isinstance(value, RequestSession)
    session = value
    events.append(f"session-closed-{session.number}")


SESSION = inject(RequestSession)


def session_info(session: RequestSession = SESSION) -> dict[str, int]:
    return {"session": session.number}


def build_app() -> FastAPI:
    global session_number
    events.clear()
    session_number = 0
    definition = ApplicationDefinition(
        routes=(route("/sessions", session_info),),
        providers=(
            provide(
                ConnectionPool,
                factory=create_pool,
                scope=Scope.APPLICATION,
                eager=True,
                disposer=close_pool,
            ),
            provide(
                RequestSession,
                factory=create_session,
                dependencies=(ConnectionPool,),
                scope=Scope.REQUEST,
                disposer=close_session,
            ),
        ),
    )
    return FastAPIAdapter.create_app(definition, title="Scopes example")


if __name__ == "__main__":
    with TestClient(build_app()) as client:
        first = client.get("/sessions")
        second = client.get("/sessions")

        assert first.json() == {"session": 1}
        assert second.json() == {"session": 2}

    assert events == [
        "pool-created",
        "session-created-1",
        "session-closed-1",
        "session-created-2",
        "session-closed-2",
        "pool-closed",
    ]
    print("06_scopes_and_cleanup: OK")
