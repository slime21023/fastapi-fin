# FastAPI integration

Use native `FastAPI`, `APIRouter`, and `Depends`, and pass `FastAPIIntegration(fin).lifespan` to `FastAPI(lifespan=...)`. On a parameter of an HTTP endpoint or nested dependency, write `service: Inject[Service]`, where `Service` must be an exported contract. `Inject[T]` is an `Annotated` carrying `Depends`; it does not turn the service into an OpenAPI parameter or request body. The integration adds no middleware, does not replace route classes, and does not wrap endpoints.

## Compose your own lifespan

If the app already has a lifespan, enter the context manager provided by the integration, merge the state it yields with your own data, and then `yield`. The following code can be saved as `custom_app.py`, in the same directory as `app.py` from [Getting started](getting-started.md).

```python
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from app import UserDirectory, fin
from fastapi_fin import FastAPIIntegration, Inject

integration = FastAPIIntegration(fin)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[dict[str, object]]:
    async with integration.lifespan(app) as state:
        yield {**state, "service_name": "users-api"}


app = FastAPI(lifespan=lifespan)


@app.get("/users/{user_id}")
async def user_info(
    user_id: int, request: Request, directory: Inject[UserDirectory]
) -> dict[str, str | None]:
    return {
        "service": request.state.service_name,
        "name": directory.find_name(user_id),
    }
```

Keep the state keys returned by the integration; do not overwrite them with your own values. The container reaches `request.state` through ASGI lifespan state and is not stored in `app.state`. In tests, use `with TestClient(app)`; creating a client without entering the context does not start the lifespan.

## Requests, validation, and limitations

- `Inject` within the same HTTP request shares one Dishka `Scope.REQUEST` container. If a module needs to read the current request, it can declare `fastapi.Request` in `requires`, and a REQUEST-scope provider obtains it through an ordinary `request: Request` parameter. If an endpoint only needs the request object, use the native `Request` parameter directly instead of `Inject[Request]`.
- At startup, the integration checks the registered FastAPI HTTP routes and recognizable nested dependencies (including a router's `dependencies`); injecting an unexported contract raises `AssemblyError`. Exceptions raised by service factories during resolution are not wrapped and can be handled by native FastAPI exception handling.
- Mounted (`mount`) sub-apps are outside the parent app's startup scan. If the parent app provides state through its lifespan, HTTP requests to a mounted sub-app can still use that container; this does not mean the parent app has validated the sub-app's injections.
- `Inject` supports HTTP only, not WebSocket; if the startup scan finds `Inject` on a WebSocket route, it raises `AdapterError`. Non-HTTP code should use [`open_container()`](scopes.md) to obtain services directly.
