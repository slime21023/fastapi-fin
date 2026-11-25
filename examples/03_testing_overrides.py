"""Test an app factory with a replacement for an exported contract."""

from typing import Protocol

from dishka import Provider, Scope, provide
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fin import FastAPIIntegration, FinComposition, Inject, Module


class Greeting(Protocol):
    def message(self) -> str: ...


class DefaultGreeting:
    def message(self) -> str:
        return "Welcome!"


class TestGreeting:
    def message(self) -> str:
        return "Hello from the test!"


class GreetingProvider(Provider):
    greeting = provide(DefaultGreeting, provides=Greeting, scope=Scope.APP)


def create_app(composition: FinComposition) -> FastAPI:
    app = FastAPI(lifespan=FastAPIIntegration(composition).lifespan)

    @app.get("/greeting")
    async def read_greeting(greeting: Inject[Greeting]) -> dict[str, str]:
        return {"message": greeting.message()}

    return app


def main() -> None:
    greetings = Module("greetings", providers=(GreetingProvider(),), exports=(Greeting,))
    composition = FinComposition(modules=(greetings,))
    test_composition = composition.with_overrides({Greeting: TestGreeting()})

    with TestClient(create_app(test_composition)) as client:
        response = client.get("/greeting")
        assert response.status_code == 200
        assert response.json() == {"message": "Hello from the test!"}

    with TestClient(create_app(composition)) as client:
        response = client.get("/greeting")
        assert response.status_code == 200
        assert response.json() == {"message": "Welcome!"}

    print("03_testing_overrides: OK")


if __name__ == "__main__":
    main()
