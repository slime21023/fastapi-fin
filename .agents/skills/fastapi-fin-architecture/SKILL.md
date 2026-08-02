---
name: fastapi-fin-architecture
description: Enforce the FastAPI-Fin architecture when implementing, reviewing, or refactoring metadata, DI, Guard, Interceptor, Event, Config, or Adapter modules; use it whenever a change could affect layer boundaries, immutability, FastAPI compatibility, or public package APIs.
---

# FastAPI-Fin Architecture

Use this skill to keep FastAPI-Fin a framework extension rather than a FastAPI rewrite. Keep the engineering core independent from FastAPI and concentrate all framework integration in the Adapter boundary.

## Design Rules

- Use the current package boundaries and public API documented in `README.md`, `docs/usage.md`,
  and `CONTRIBUTING.md` when making architectural changes.
- Keep dependency direction flowing toward abstractions and the Adapter boundary: application declarations → metadata → engineering modules → Adapter → public FastAPI/ASGI contracts.
- Do not import FastAPI from metadata, DI, Guard, Interceptor, Event, or Config core modules. Only Adapter code may call FastAPI APIs.
- Use only public, documented FastAPI exports and ASGI protocols in the Adapter. Never depend on private modules, undocumented attributes, or Starlette internals that FastAPI does not expose.
- Treat completed metadata, bindings, guard rules, interceptor chains, subscriptions, and configuration as immutable snapshots. Combine or replace them by creating new values; do not mutate shared runtime state.
- Validate decorator and registration inputs immediately, normalize loose inputs at registration time, and fail with a precise exception before application startup.
- Preserve endpoint signatures when wrapping callables so FastAPI parameter resolution and OpenAPI generation remain intact.
- Keep modules independently adoptable; do not require consumers to enable every subsystem.
- Use type hints for public APIs and make sensitive configuration explicit so logging can mask it.

## Change Workflow

1. Identify the layer being changed and its allowed dependencies.
2. Define or update the immutable internal value first; keep framework conversion at the Adapter edge.
3. Add declaration-time validation and normalization for every new public input.
4. Expose the smallest stable public API and update `__all__` where appropriate.
5. Add the matching unit, contract, or integration tests using `$fastapi-fin-testing`.
6. Run `uv run ruff format --check .`, `uv run ruff check .`, and `uv run ty check`.

## Review Checklist

- Is the module in the correct layer?
- Does any non-Adapter module import FastAPI or private framework symbols?
- Are all composed structures immutable and built as new snapshots?
- Are invalid paths, HTTP methods, lifecycles, policies, retry/timeout values, and config values rejected early?
- Does the Adapter use only documented FastAPI APIs while preserving OpenAPI and Pydantic behavior?
- Can the core behavior be tested without starting FastAPI?
- Is the public API compatible with semantic versioning and the existing package exports?
