from typing import cast

import pytest

from fastapi_fin.application import (
    connect,
    controller,
    delete,
    get,
    head,
    module,
    options,
    patch,
    post,
    put,
    trace,
)
from fastapi_fin.core import DeclarationError, GuardRule, HttpMethod, InterceptorSpec
from fastapi_fin.core.metadata import get_controller_metadata, get_route_metadata


@controller(prefix="/users")
class UserController:
    @get("/")
    def list_users(self) -> list[str]:
        return []

    @post("/")
    def create_user(self) -> str:
        return "created"


def test_controller_decorator_collects_routes_in_declaration_order() -> None:
    metadata = get_controller_metadata(UserController)

    assert [route.path for route in metadata.routes] == ["/users/", "/users/"]
    assert [route.methods for route in metadata.routes] == [
        (HttpMethod.GET,),
        (HttpMethod.POST,),
    ]


@pytest.mark.parametrize(
    ("decorator", "method"),
    [
        (connect, HttpMethod.CONNECT),
        (delete, HttpMethod.DELETE),
        (head, HttpMethod.HEAD),
        (options, HttpMethod.OPTIONS),
        (patch, HttpMethod.PATCH),
        (put, HttpMethod.PUT),
        (trace, HttpMethod.TRACE),
    ],
)
def test_http_method_decorators_create_single_method_metadata(decorator, method) -> None:
    @decorator("/")
    def endpoint() -> str:
        return "ok"

    assert get_route_metadata(endpoint).methods == (method,)


def test_route_decorator_normalizes_openapi_options_without_fastapi() -> None:
    @get(
        "/",
        response_model=None,
        status_code=201,
        tags=(" users ", "users"),
        summary=" Create user ",
        description=" Creates a user ",
        response_description=" Created ",
        operation_id="create-user",
    )
    def endpoint() -> None:
        return None

    metadata = get_route_metadata(endpoint)

    assert metadata.has_response_model is True
    assert metadata.response_model is None
    assert metadata.status_code == 201
    assert metadata.tags == ("users",)
    assert metadata.summary == "Create user"
    assert metadata.description == "Creates a user"
    assert metadata.response_description == "Created"
    assert metadata.operation_id == "create-user"


def test_route_decorator_rejects_invalid_openapi_options() -> None:
    def invalid_status() -> None:
        return None

    def invalid_tag() -> None:
        return None

    with pytest.raises(DeclarationError):
        get("/", status_code=99)(invalid_status)
    with pytest.raises(DeclarationError):
        get("/", tags=("",))(invalid_tag)


def test_controller_decorator_rejects_non_iterable_policy_options() -> None:
    with pytest.raises(DeclarationError, match="controller guards must be iterable"):
        controller(guards=cast("tuple[GuardRule, ...]", None))(type("Controller", (), {}))

    with pytest.raises(DeclarationError, match="controller interceptors must be iterable"):
        controller(interceptors=cast("tuple[InterceptorSpec, ...]", None))(
            type("Controller", (), {})
        )


def test_module_decorator_rejects_non_iterable_composition_options() -> None:
    with pytest.raises(DeclarationError, match="module controllers must be iterable"):
        module(controllers=cast("tuple[type[object], ...]", None))(type("Module", (), {}))

    with pytest.raises(DeclarationError, match="module modules must be iterable"):
        module(modules=cast("tuple[type[object], ...]", None))(type("Module", (), {}))
