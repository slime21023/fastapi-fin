# FastAPI-Fin examples

The examples live in the source repository. After getting the source code, run `uv sync --locked` in the project root, then run:

```powershell
uv run python examples/01_modules_and_contracts.py
uv run python examples/02_scopes_and_finalization.py
uv run python examples/03_testing_overrides.py
uv run python examples/04_without_fastapi.py
uv run python examples/05_validation_failures.py
uv run python examples/06_security_jwt.py
uv run python examples/07_resource_authorization.py
uv run python examples/08_revocation_and_rate_limits.py
uv run python -m examples.complete_app
```

The numbered scripts show cross-module contracts, resource cleanup, test overrides, resolving without HTTP, assembly failures, JWT, per-resource authorization, and token revocation with rate limiting. The [complete Task API](complete_app/README.md) keeps services, authentication, and HTTP routes in separate modules.
