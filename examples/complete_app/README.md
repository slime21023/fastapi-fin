# Complete Task API

A complete multi-file example that shows how to compose FastAPI-Fin into a small, maintainable application. It uses an in-memory repository, so no database or external service is needed.

## Run

From the project root:

```powershell
uv run python -m examples.complete_app
```

On success it prints `complete_app: OK`. The example signs JWTs with a temporary key and verifies the behavior through `TestClient`: `GET /tasks` needs no login; `POST /tasks` returns `401` when the bearer token is missing or invalid and `403` when a valid token lacks the `admin` role; an admin can create a task and see it in the list.

## Reading order

1. `domain.py`: Pydantic request/response models and the `TaskService` Protocol.
2. `providers.py`: the `tasks` module provides an internal APP-scope repository with Dishka and exports only the REQUEST-scope `TaskService`; the `auth` module exports `TokenAuthenticator`, implemented by `JwtVerifier`.
3. `routes.py`: a native `APIRouter` gets the service with `Inject[TaskService]` and applies the admin role rule with `FastAPISecurity`.
4. `app.py`: `create_app(composition)` wires the container with `FastAPIIntegration.lifespan` and mounts the router; `run_demo()` composes the modules into a `FinComposition` and runs the HTTP checks.
