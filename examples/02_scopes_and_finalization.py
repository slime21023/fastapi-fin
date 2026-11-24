"""Commit or roll back a request session and close its pool on shutdown."""

from collections.abc import AsyncIterator

from dishka import Provider, Scope, provide
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin import Application, FastAPIIntegration, Inject, Module


class Pool:
    def __init__(self) -> None:
        self.saved: list[str] = []
        self.closed = False


class Session:
    def __init__(self, pool: Pool) -> None:
        self._pool = pool
        self.pending: list[str] = []

    def commit(self) -> None:
        self._pool.saved.extend(self.pending)
        self.pending.clear()

    def rollback(self) -> None:
        self.pending.clear()


class StorageProvider(Provider):
    def __init__(self, pool: Pool) -> None:
        super().__init__()
        self._pool = pool

    @provide(scope=Scope.APP)
    async def pool(self) -> AsyncIterator[Pool]:
        try:
            yield self._pool
        finally:
            self._pool.closed = True

    @provide(scope=Scope.REQUEST)
    async def session(self, pool: Pool) -> AsyncIterator[Session]:
        session = Session(pool)
        error = yield session
        if error is None:
            session.commit()
        else:
            session.rollback()


def main() -> None:
    pool = Pool()
    storage = Module("storage", providers=(StorageProvider(pool),), exports=(Session,))
    app = FastAPI(lifespan=FastAPIIntegration(Application(modules=(storage,))).lifespan)

    @app.post("/items/{name}")
    async def save_item(name: str, session: Inject[Session], fail: bool = False) -> None:
        session.pending.append(name)
        if fail:
            raise RuntimeError("cannot save item")

    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.post("/items/kept").status_code == 200
        assert pool.saved == ["kept"]
        assert client.post("/items/discarded?fail=true").status_code == 500
        assert pool.saved == ["kept"]
        assert not pool.closed

    assert pool.closed
    print("02_scopes_and_finalization: OK")


if __name__ == "__main__":
    main()
