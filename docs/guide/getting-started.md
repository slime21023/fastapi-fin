# Installation and your first app

FastAPI-Fin 0.9.1 requires Python 3.12 or later. Install it with:

```console
pip install fastapi-fin
```

With uv, use `uv add fastapi-fin` instead.

## Define a service contract and wire it to a route

The example below uses `UserDirectory` to describe the capability a route needs, so the route does not need to know where user data is stored.
Dishka's `@provide` registers the contract by its return type, and `Module.exports` exposes the contract to routes.
The route itself is still declared with native FastAPI.

Save the following code as `app.py`. The `TestClient` check at the end requires httpx; install it with `pip install httpx httpx2` (httpx2 is used by Starlette 1.x).

```python
from typing import Protocol

from dishka import Provider, Scope, provide
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fastapi_fin import FastAPIIntegration, FinComposition, Inject, Module


class UserDirectory(Protocol):
    def find_name(self, user_id: int) -> str | None: ...


class InMemoryDirectory:
    def __init__(self, names: dict[int, str]) -> None:
        self._names = names

    def find_name(self, user_id: int) -> str | None:
        return self._names.get(user_id)


class UsersProvider(Provider):
    @provide(scope=Scope.APP)
    def directory(self) -> UserDirectory:
        return InMemoryDirectory({42: "Alice"})


composition = FinComposition(
    modules=(
        Module(
            name="users",
            providers=(UsersProvider(),),
            exports=(UserDirectory,),
        ),
    ),
)


def create_app(composition: FinComposition) -> FastAPI:
    integration = FastAPIIntegration(composition)
    app = FastAPI(lifespan=integration.lifespan)

    @app.get("/users/{user_id}")
    async def get_user(user_id: int, directory: Inject[UserDirectory]) -> dict[str, str]:
        name = directory.find_name(user_id)
        if name is None:
            raise HTTPException(status_code=404, detail="User not found")
        return {"name": name}

    return app


app = create_app(composition)

if __name__ == "__main__":
    with TestClient(app) as client:
        response = client.get("/users/42")
        assert response.status_code == 200
        assert response.json() == {"name": "Alice"}
```

Run `uv run python app.py` to verify the example. `TestClient` must be started with `with` so that
the lifespan runs and passes the container to HTTP requests. `user_id` is still parsed and validated by FastAPI;
`directory` is a dependency, not an HTTP parameter.

## Run with Uvicorn

Hand the same `app` to Uvicorn:

```console
pip install uvicorn
uvicorn app:app
```

The `if __name__ == "__main__":` block runs only with `python app.py`; Uvicorn does not run it. The lifespan creates the container when the server starts and cleans it up when the server shuts down. For details, see [Running with Uvicorn](deployment.md).

Next, read [Modules and contracts](modules.md) and [FastAPI integration](fastapi.md), or
[test with contract overrides](testing.md).
