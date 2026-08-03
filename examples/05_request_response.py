"""Use Pydantic request/response models with explicit route metadata."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationDefinition, route


class UserCreate(BaseModel):
    name: str = Field(min_length=1)
    age: int = Field(ge=0)


class UserView(BaseModel):
    id: int
    name: str
    age: int
    verbose: bool


def create_user(payload: UserCreate, verbose: bool = False) -> UserView:
    return UserView(id=1, name=payload.name, age=payload.age, verbose=verbose)


def build_app() -> FastAPI:
    definition = ApplicationDefinition(
        routes=(
            route(
                "/users",
                create_user,
                methods="POST",
                response_model=UserView,
                status_code=201,
                tags=("users",),
                summary="Create one user",
                operation_id="create_user",
            ),
        ),
    )
    return FastAPIAdapter.create_app(definition, title="Request/response example")


if __name__ == "__main__":
    with TestClient(build_app()) as client:
        response = client.post(
            "/users?verbose=true",
            json={"name": "Ada", "age": 36},
        )
        invalid = client.post("/users", json={"name": "", "age": -1})

        assert response.status_code == 201
        assert response.json() == {
            "id": 1,
            "name": "Ada",
            "age": 36,
            "verbose": True,
        }
        assert invalid.status_code == 422
        assert (
            "create_user"
            in client.get("/openapi.json").json()["paths"]["/users"]["post"]["operationId"]
        )

    print("05_request_response: OK")
