# Contributing to FastAPI-Fin

## Development environment

```powershell
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest --cov=fastapi_fin --cov-fail-under=85
uv run bandit -q -r fastapi_fin
uv run zensical build --strict
uv build
```

Ruff checks type annotations, docstrings, function complexity, unused arguments, line length, and security rules. If a framework contract or test data genuinely needs an exception, scope it as narrowly as possible and state the rule code and the reason.

`ty` runs with `all = "error"`, so every rule is an error. Typing conventions: declare aliases with the Python 3.12 `type` statement (for example `Contract` and `ModuleName`), write generic functions as `def f[T](...)`, return the own type with `Self`, and use `@frozen` for immutable attrs classes. Avoid `Any` and `cast` in library code; when unavoidable, use them in the smallest possible scope and explain why.

## Loops and performance

Unless the algorithm requires it (for example, recursively walking a dependency tree), avoid nested loops. That includes nested comprehensions and `in` lookups on a `tuple` or `list` inside a loop. Use `set` or `dict` lookups, set operations, or flatten with `itertools.chain.from_iterable` and iterate once; give each loop level a small named function. `tests/test_code_rules.py` checks `fastapi_fin/` and `examples/` for nested loops (`in` lookups need manual review).

## Architecture boundaries

- `fastapi_fin/modules.py` validates immutable `Module` and `FinComposition` declarations. Providers are handed to a module once built and are not modified in place afterwards.
- `fastapi_fin/container.py` connects exports and requires to Dishka components. Dishka owns the dependency graph, scopes, caching, and cleanup; do not reimplement a runtime.
- `fastapi_fin/security/` (JWT, principal, policy, and the authenticator contract) does not depend on FastAPI.
- Only `fastapi_fin/adapters/` may import FastAPI. The integration uses native dependencies and the lifespan; it does not use `dishka.integrations`, custom routing, or middleware.
- Assembly keeps the original Dishka graph error as the cause; factory exceptions are not wrapped at runtime.
- Naming: `FastAPI*` classes live in `adapters/` and depend on FastAPI; `Fin*` classes are framework-independent; `app` always means a FastAPI instance and `composition` a `FinComposition`.

## Tests and documentation

- Unit: `tests/unit` verifies contracts, scopes, and JWT without starting FastAPI.
- Contract: `tests/contract` uses `with TestClient(app)` to verify HTTP/OpenAPI, lifespan, and authentication behavior.
- Integration: `uv run pytest -m integration` runs all examples and verifies lifespan startup, shutdown, and multi-worker behavior with real Uvicorn servers (`tests/integration/test_uvicorn.py`). CI runs this as its own step; the remaining tests run with `-m "not integration"`.
- When you change `docs/`, update the navigation in `zensical.toml` too. Preview locally with `uv run zensical serve`. Documentation is written in English.

## Releasing

There is no automated release workflow. The steps are:

1. Sync the version in `pyproject.toml` and `fastapi_fin/__init__.py` (`tests/test_package.py` checks this), update `CHANGELOG.md`, and run `uv lock`.
2. Push and confirm CI passes in full.
3. Run `uv build` and `uvx twine check dist/*`. Check that the wheel contains only `fastapi_fin/` and the license file, and that the sdist does not contain `.agents/`.
4. Create and push the tag: `git tag v<version> && git push origin v<version>`.
5. Upload with `uv publish` (requires a PyPI token).
