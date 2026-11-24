# Testing and overrides

`Application.with_overrides({Contract: fake})` replaces an object behind a public contract without changing routes,
providers or the existing `Application`. The key must be an exported contract, and the value is a prepared instance, not a factory.
The fake is provided in `Scope.APP`: HTTP injection, requires from other modules, and dependencies on that contract inside the exporting module
all receive the same object. If the same contract is overridden more than once, the last override wins.

Each test can create its own fake and `Application`, which avoids sharing mutable state across tests. Even when a new container is created,
the container uses the object you passed in and does not copy it.

## Without starting FastAPI

The example below reuses the example saved as `app.py` in [Getting started](getting-started.md). Use `open_container()`
to verify dependency assembly and overrides directly. To keep a test from importing FastAPI at all, put the module declarations and service types
in a separate Python module that both the HTTP entry point and the tests import.

```python
import asyncio

from app import InMemoryDirectory, UserDirectory, application

from fastapi_fin import open_container


def test_directory_override() -> None:
    fake = InMemoryDirectory({42: "Test user"})

    async def check() -> None:
        async with open_container(application.with_overrides({UserDirectory: fake})) as root:
            assert await root.get(UserDirectory) is fake

    asyncio.run(check())
```

To test `Scope.REQUEST` services, first read about [child scopes](scopes.md).

## Testing HTTP behavior

Pass the overridden declaration to the app factory. Use `with TestClient(...)` to run the lifespan,
so requests receive the ASGI state the container needs and resources are cleaned up when the test ends.

```python
from fastapi.testclient import TestClient

from app import InMemoryDirectory, UserDirectory, application, create_app


def test_get_user() -> None:
    fake = InMemoryDirectory({42: "Test user"})
    app = create_app(application.with_overrides({UserDirectory: fake}))

    with TestClient(app) as client:
        response = client.get("/users/42")

    assert response.status_code == 200
    assert response.json() == {"name": "Test user"}
```

## Test layers in this project

- Unit: no FastAPI; verifies module declarations, the Dishka dependency graph and cleanup.
- Contract: uses `TestClient` and the lifespan to verify native routes, HTTP injection and OpenAPI behavior.
- Integration: runs the [examples](../examples/index.md) to confirm the full flow works after real assembly.
