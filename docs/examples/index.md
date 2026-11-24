# Examples

The examples live in the source code repository. After obtaining the source code, run `uv sync --locked` in the project root. Each example verifies its behavior and then prints its own `OK` message.

| Command | What to observe |
| --- | --- |
| `uv run python examples/01_modules_and_contracts.py` | Connecting cross-module services through a Protocol. |
| `uv run python examples/02_scopes_and_finalization.py` | APP and REQUEST scopes; cleanup on success and on error. |
| `uv run python examples/03_testing_overrides.py` | Building an isolated test app with fakes. |
| `uv run python examples/04_without_fastapi.py` | A worker obtains services without HTTP. |
| `uv run python examples/05_validation_failures.py` | Contract conflicts, missing contracts, and unexported dependencies. |
| `uv run python examples/06_security_jwt.py` | Injecting an authenticator and using FastAPI bearer security. |
| `uv run python -m examples.complete_app` | A Task API that separates services, authentication, and HTTP. |
