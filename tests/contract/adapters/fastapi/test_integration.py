import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated
from uuid import uuid4

from dishka import Provider, Scope, provide
from fastapi import APIRouter, Depends, FastAPI, Request, Security, WebSocket
from fastapi.responses import JSONResponse
from fastapi.security import SecurityScopes
from fastapi.testclient import TestClient
from pydantic import BaseModel
import pytest

from fastapi_fin.adapters import FastAPIIntegration, Inject
from fastapi_fin.errors import AdapterError, AssemblyError
from fastapi_fin.modules import Application, Module


def test_injection_shares_request_scope_and_retains_app_scope() -> None:
    @dataclass
    class AppToken:
        value: str

    @dataclass
    class RequestToken:
        value: str

    class Tokens(Provider):
        @provide(scope=Scope.APP)
        def app_token(self) -> AppToken:
            return AppToken(uuid4().hex)

        @provide(scope=Scope.REQUEST)
        def request_token(self) -> RequestToken:
            return RequestToken(uuid4().hex)

    integration = FastAPIIntegration(
        Application((Module("tokens", providers=(Tokens(),), exports=(AppToken, RequestToken)),))
    )
    app = FastAPI(lifespan=integration.lifespan)

    async def nested(token: Inject[RequestToken], scopes: SecurityScopes) -> RequestToken:
        assert scopes.scopes == ["example:read"]
        return token

    @app.get("/tokens")
    async def tokens(
        token: Inject[RequestToken],
        nested_token: Annotated[RequestToken, Security(nested, scopes=["example:read"])],
        app_token: Inject[AppToken],
    ) -> dict[str, str]:
        assert token is nested_token
        return {"request": token.value, "app": app_token.value}

    with TestClient(app) as client:
        first = client.get("/tokens")
        second = client.get("/tokens")

    assert first.status_code == second.status_code == 200
    assert first.json()["request"] != second.json()["request"]
    assert first.json()["app"] == second.json()["app"]
    operation = app.openapi()["paths"]["/tokens"]["get"]
    assert "parameters" not in operation
    assert "requestBody" not in operation


def test_request_finalizer_receives_endpoint_exception() -> None:
    class Session:
        pass

    seen: list[BaseException | None] = []
    failure = RuntimeError("endpoint failed")

    class Sessions(Provider):
        @provide(scope=Scope.REQUEST)
        async def session(self) -> AsyncIterator[Session]:
            error = yield Session()
            seen.append(error)

    integration = FastAPIIntegration(
        Application((Module("sessions", providers=(Sessions(),), exports=(Session,)),))
    )
    app = FastAPI(lifespan=integration.lifespan)

    @app.get("/fail")
    async def fail(session: Inject[Session]) -> None:
        raise failure

    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/fail").status_code == 500
        assert seen == [failure]


def test_provider_exception_reaches_native_exception_handler() -> None:
    class Service:
        pass

    class ServiceUnavailableError(Exception):
        pass

    class Services(Provider):
        @provide(scope=Scope.REQUEST)
        def service(self) -> Service:
            raise ServiceUnavailableError("service is offline")

    integration = FastAPIIntegration(
        Application((Module("services", providers=(Services(),), exports=(Service,)),))
    )
    app = FastAPI(lifespan=integration.lifespan)

    @app.exception_handler(ServiceUnavailableError)
    async def handle_unavailable(request: Request, error: ServiceUnavailableError) -> JSONResponse:
        return JSONResponse({"detail": str(error)}, status_code=503)

    @app.get("/service")
    async def service(value: Inject[Service]) -> None:
        raise AssertionError("endpoint should not run if dependency resolution fails")

    with TestClient(app) as client:
        response = client.get("/service")

    assert response.status_code == 503
    assert response.json() == {"detail": "service is offline"}


@pytest.mark.parametrize("location", ["endpoint", "nested", "router"])
def test_startup_rejects_http_injection_of_unexported_contract(location: str) -> None:
    class Missing:
        pass

    integration = FastAPIIntegration(Application())
    app = FastAPI(lifespan=integration.lifespan)

    async def needs_missing(value: Inject[Missing]) -> None:
        pass

    if location == "endpoint":
        app.get("/missing")(needs_missing)
    elif location == "nested":

        @app.get("/missing")
        async def nested(value: Annotated[None, Depends(needs_missing)]) -> None:
            pass
    else:
        router = APIRouter(dependencies=[Depends(needs_missing)])

        @router.get("/missing")
        async def endpoint() -> None:
            pass

        app.include_router(router)

    async def startup() -> None:
        async with integration.lifespan(app):
            pass

    with pytest.raises(AssemblyError, match=r"route '/missing' injects .*Missing.*not an exported"):
        asyncio.run(startup())


def test_startup_rejects_websocket_injection_even_for_exported_contract() -> None:
    class Service:
        pass

    class Services(Provider):
        service = provide(Service, scope=Scope.APP)

    integration = FastAPIIntegration(
        Application((Module("services", providers=(Services(),), exports=(Service,)),))
    )
    app = FastAPI(lifespan=integration.lifespan)

    @app.websocket("/socket")
    async def socket(websocket: WebSocket, service: Inject[Service]) -> None:
        await websocket.close()

    async def startup() -> None:
        async with integration.lifespan(app):
            pass

    with pytest.raises(AdapterError, match="Inject is not supported on WebSocket route '/socket'"):
        asyncio.run(startup())


def test_request_injection_requires_integration_lifespan() -> None:
    class Service:
        pass

    app = FastAPI()

    @app.get("/service")
    async def service(value: Inject[Service]) -> None:
        pass

    with (
        TestClient(app) as client,
        pytest.raises(AdapterError, match=r"FastAPIIntegration\.lifespan"),
    ):
        client.get("/service")


def test_user_lifespan_composes_state_with_injection_and_supplies_request_context() -> None:
    @dataclass
    class RequestHeader:
        value: str

    class Headers(Provider):
        @provide(scope=Scope.REQUEST)
        def request_header(self, request: Request) -> RequestHeader:
            return RequestHeader(request.headers["x-contract-test"])

    integration = FastAPIIntegration(
        Application(
            (
                Module(
                    "headers", providers=(Headers(),), exports=(RequestHeader,), requires=(Request,)
                ),
            )
        )
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[dict[str, object]]:
        async with integration.lifespan(app) as state:
            yield {**state, "custom": "custom state"}

    app = FastAPI(lifespan=lifespan)

    @app.get("/header")
    async def header(request: Request, injected: Inject[RequestHeader]) -> dict[str, str]:
        return {"header": injected.value, "state": request.state.custom}

    with TestClient(app) as client:
        response = client.get("/header", headers={"x-contract-test": "current request"})

    assert response.status_code == 200
    assert response.json() == {"header": "current request", "state": "custom state"}


def test_contract_override_preserves_native_validation_and_dependency_overrides() -> None:
    @dataclass
    class Repo:
        name: str = "original"

    class Item(BaseModel):
        quantity: int

    class Repos(Provider):
        @provide(scope=Scope.APP)
        def repo(self) -> Repo:
            return Repo()

    replacement = Repo("replacement")
    application = Application((Module("repos", providers=(Repos(),), exports=(Repo,)),))
    integration = FastAPIIntegration(application.with_overrides({Repo: replacement}))
    app = FastAPI(lifespan=integration.lifespan)

    async def label() -> str:
        return "original label"

    async def override_label() -> str:
        return "overridden label"

    app.dependency_overrides[label] = override_label

    @app.post("/items/{item_id}")
    async def create_item(
        item_id: int, item: Item, repo: Inject[Repo], display_label: Annotated[str, Depends(label)]
    ) -> dict[str, str | int]:
        assert repo is replacement
        return {
            "id": item_id,
            "quantity": item.quantity,
            "repo": repo.name,
            "label": display_label,
        }

    with TestClient(app) as client:
        invalid_path = client.post("/items/not-an-int", json={"quantity": 2})
        invalid_body = client.post("/items/1", json={"quantity": "not-an-int"})
        valid = client.post("/items/1", json={"quantity": 2})

    assert invalid_path.status_code == invalid_body.status_code == 422
    assert invalid_path.json()["detail"][0]["loc"] == ["path", "item_id"]
    assert invalid_body.json()["detail"][0]["loc"] == ["body", "quantity"]
    assert valid.status_code == 200
    assert valid.json() == {
        "id": 1,
        "quantity": 2,
        "repo": "replacement",
        "label": "overridden label",
    }
