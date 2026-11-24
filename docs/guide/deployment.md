# Running with Uvicorn

FastAPI-Fin needs only the ASGI lifespan, so running it with Uvicorn is the same as for an ordinary FastAPI app; no extra configuration, middleware, or startup script is needed.

## Start

Save the app from [Getting started](getting-started.md) as `main.py`, and make sure `app = FastAPI(lifespan=FastAPIIntegration(...).lifespan)` is at module level:

```console
uvicorn main:app
```

Multiple workers also work:

```console
uvicorn main:app --workers 2
```

These scenarios are verified automatically against a real Uvicorn server by `tests/integration/test_uvicorn.py` and run in CI: command-line startup with a single process and with `--workers 2`, a programmatically started `uvicorn.Server`, cleanup after graceful shutdown, and startup validation failure.

## What happens at startup and shutdown

- **Startup**: when Uvicorn enters the lifespan, the integration creates a new container and scans the routes for `Inject`. If a route injects an unexported contract, `AssemblyError` is raised, Uvicorn prints `Application startup failed. Exiting.` and exits with a non-zero status, and no requests are accepted.
- **Shutdown**: when Uvicorn receives `SIGINT`/`SIGTERM` or asks to exit by itself, it closes the lifespan, the container closes with it, and generator factories in `Scope.APP` run their cleanup. Forcibly terminating the process (e.g. `kill -9`, or `TerminateProcess` on Windows) does not run cleanup.
- **Each request**: `Inject` enters a `Scope.REQUEST` child container for that request, and the resources of that scope are cleaned up when the request ends.

## Multiple workers

Each worker is a separate process that runs its own lifespan and builds its own container. Therefore a `Scope.APP` instance exists "once per worker" and is not a global singleton: connection pools multiply with the number of workers, and in-memory caches or counters are not shared between workers. State that must be shared across workers should live in an external service, such as a database or cache server.

## Create APP resources at startup

A `Scope.APP` factory runs the first time it is resolved, not automatically when the lifespan starts. To confirm that the database is reachable before accepting requests, resolve the exported contract ahead of time in your own lifespan; the root container is under the `CONTAINER_STATE_KEY` key of the state yielded by the integration:

```python
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from fastapi_fin import CONTAINER_STATE_KEY, FastAPIIntegration

integration = FastAPIIntegration(application)  # your Application, with Database exported


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[dict[str, object]]:
    async with integration.lifespan(app) as state:
        await state[CONTAINER_STATE_KEY].get(Database)  # on failure, Uvicorn does not start serving
        yield state


app = FastAPI(lifespan=lifespan)
```

Early resolution applies only to exported contracts in `Scope.APP`; `Scope.REQUEST` services must be resolved inside the request's child container.

## Verification coverage

- The CI test matrix (Linux; Python 3.12 and 3.13; FastAPI 0.115.11 with Starlette 0.46.2, and FastAPI 0.141.1 with Starlette 1.3.1) runs these tests against the locked Uvicorn.
- FastAPI 0.141.1 with Uvicorn 0.24.0, 0.27.1, 0.28.1, and 0.29.0 was also verified manually; these versions are not in the CI matrix.
- `--reload`, other ASGI servers (such as Hypercorn), and Gunicorn's Uvicorn workers are not verified.
