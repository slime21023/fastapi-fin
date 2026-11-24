---
name: fastapi-fin-testing
description: Design FastAPI-Fin unit, contract, and integration coverage for service composition, Dishka scopes, security, and HTTP lifecycle.
---

# FastAPI-Fin Testing

Test the public service and HTTP contracts, not provider registration internals.

- Unit: use ordinary pytest in `tests/unit`. Compose Dishka providers and enter scopes through `open_container()` or test a service directly with constructor injection. Do not import or start FastAPI.
- Contract: use `with TestClient(app)` in `tests/contract` so ASGI lifespan state reaches HTTP requests. Assert resolved values, request and application scope boundaries, cleanup, validation, OpenAPI output, and 401/403 semantics as applicable.
- Integration: mark executable application examples with `integration`. Verify application results and resource cleanup without external services.
- To replace a service, start a fresh app with `Application.with_overrides()`. Native FastAPI dependency overrides remain available for HTTP-layer dependencies.

Run the focused test first. Run `uv run pytest -m integration` for example changes; CI also runs the full suite with coverage.

