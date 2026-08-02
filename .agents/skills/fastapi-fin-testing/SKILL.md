---
name: fastapi-fin-testing
description: Design and review FastAPI-Fin pytest coverage using the project's unit, contract, and integration test layers; use it when adding tests for DI, Guard, Interceptor, Event, Config, metadata, Adapter behavior, lifecycle handling, or FastAPI compatibility.
---

# FastAPI-Fin Testing

Keep most tests fast and framework-independent while reserving a small contract suite for the FastAPI Adapter. Every test should make the boundary and lifecycle assumptions in `_design.md` observable.

## Test Layers

- **Unit tests**: test metadata, DI, Guard, Interceptor, Event, and Config pure logic without importing or starting FastAPI. Cover normal behavior, invalid inputs, normalization, precedence, and immutable snapshot composition.
- **Contract tests**: build a minimal FastAPI application and verify Adapter translation through public APIs such as `APIRouter`, `Depends`, and lifespan. Check endpoint signatures, request/response validation, dependency execution, OpenAPI output, and error translation.
- **Integration tests**: exercise the complete startup/lifespan/request flow with a real HTTP client. Mark them `integration` and keep external services isolated behind fakes.

## Test Workflow

1. Classify the behavior as unit, contract, or integration before writing code.
2. Prefer Arrange–Act–Assert and focused fixtures. Use `pytest.mark.parametrize` for validation matrices and boundary values.
3. Assert observable results and immutable replacement semantics; do not assert private implementation details.
4. For async behavior, use async pytest support and test cancellation, ordering, and exception propagation where relevant.
5. Add explicit tests for conflicting Guards, invalid interceptor settings, duplicate subscriptions, sensitive config masking, and FastAPI public-contract compatibility when applicable.
6. Run the smallest relevant test first, then `uv run pytest`; use `-m "not slow and not integration"` for the fast local loop.

## Naming and Markers

- Put tests under `tests/`, grouped by layer or subsystem.
- Name tests after behavior, for example `test_registering_invalid_path_fails_early`.
- Use `@pytest.mark.integration` for end-to-end application flows and `@pytest.mark.slow` for expensive suites.
- Keep unit tests free of `TestClient` and application startup; use contract tests for the Adapter instead.
