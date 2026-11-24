"""Native FastAPI dependencies backed by the active Dishka request scope."""

from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Mapping
from contextlib import asynccontextmanager
from inspect import Parameter, signature, unwrap
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Final, get_args, get_origin

from attrs import define
from dishka import AsyncContainer, BaseScope, Scope
from fastapi import Depends, FastAPI, Request, routing
from fastapi.params import Depends as DependsMarker
from fastapi.routing import APIRoute, APIWebSocketRoute

from ..container import open_container
from ..errors import AdapterError, AssemblyError, DefinitionError
from ..modules import Application, _normalize_contract

CONTAINER_STATE_KEY: Final = "fastapi_fin_container"
_REQUEST_STATE_KEY: Final = "_fastapi_fin_request_container"
_FASTAPI_CONTEXT: Final[Mapping[object, BaseScope]] = MappingProxyType({Request: Scope.REQUEST})


async def _request_container(request: Request) -> AsyncIterator[AsyncContainer]:
    # FastAPI may use distinct cache keys for dependencies under OAuth2 scopes.
    existing = getattr(request.state, _REQUEST_STATE_KEY, None)
    if isinstance(existing, AsyncContainer):
        yield existing
        return
    root = getattr(request.state, CONTAINER_STATE_KEY, None)
    if not isinstance(root, AsyncContainer):
        raise AdapterError(
            "FastAPI-Fin container is not active; pass FastAPIIntegration.lifespan "
            "to FastAPI(lifespan=...)"
        )
    async with root(context={Request: request}, scope=Scope.REQUEST) as container:
        setattr(request.state, _REQUEST_STATE_KEY, container)
        try:
            yield container
        finally:
            delattr(request.state, _REQUEST_STATE_KEY)


@define(frozen=True, slots=True)
class _InjectDependency:
    contract: object

    async def __call__(
        self, container: Annotated[AsyncContainer, Depends(_request_container)]
    ) -> object:
        return await container.get(self.contract)


if TYPE_CHECKING:
    type Inject[T] = T
else:

    class Inject:
        """Declare an exported contract as a native FastAPI dependency."""

        def __class_getitem__(cls, contract: object) -> object:
            try:
                _normalize_contract(contract)
            except DefinitionError as error:
                raise AdapterError(
                    "Inject contract must be a hashable type hint, not a string"
                ) from error
            return Annotated[contract, Depends(_InjectDependency(contract))]


@define(frozen=True, slots=True)
class FastAPIIntegration:
    """Own the application container through an explicit FastAPI lifespan."""

    application: Application

    def __attrs_post_init__(self) -> None:
        if not isinstance(self.application, Application):
            raise AdapterError("integration application must be an Application")

    @asynccontextmanager
    async def lifespan(self, app: FastAPI) -> AsyncIterator[dict[str, object]]:
        """Build a fresh container and expose it through ASGI lifespan state."""
        if not isinstance(app, FastAPI):
            raise AdapterError("lifespan requires a FastAPI application")
        async with open_container(self.application, context=_FASTAPI_CONTEXT) as container:
            _validate_injections(app, self.application.exports)
            yield {CONTAINER_STATE_KEY: container}


def _validate_injections(app: FastAPI, exports: Mapping[object, str]) -> None:
    # Newer FastAPI versions expose included routes through route contexts.
    iter_contexts = getattr(routing, "iter_route_contexts", None)
    contexts = iter_contexts(app.routes) if iter_contexts is not None else app.routes
    for route in contexts:
        original = getattr(route, "original_route", route)
        if not isinstance(original, (APIRoute, APIWebSocketRoute)):
            continue
        seen: set[int] = set()
        endpoint = getattr(route, "endpoint", original.endpoint)
        dependencies = getattr(route, "dependencies", original.dependencies)
        path = getattr(route, "path", original.path)
        for call in (endpoint, *(dep.dependency for dep in dependencies)):
            if call is None:
                continue
            for contract in _collect_contracts(call, seen):
                if isinstance(original, APIWebSocketRoute):
                    raise AdapterError(f"Inject is not supported on WebSocket route {path!r}")
                if contract not in exports:
                    raise AssemblyError(
                        f"route {path!r} injects {contract!r}, which is not an exported contract"
                    )


def _dependency_parameters(call: Callable[..., object]) -> Iterable[Parameter]:
    target = unwrap(call)
    if isinstance(target, type):
        target = target.__init__
    elif not hasattr(target, "__globals__"):
        target = type(target).__call__
    try:
        return signature(
            call, eval_str=True, globals=getattr(target, "__globals__", None)
        ).parameters.values()
    except (NameError, TypeError, ValueError, SyntaxError):
        # FastAPI may accept annotations that inspect cannot resolve.
        try:
            return signature(call).parameters.values()
        except (TypeError, ValueError):
            return ()


def _collect_contracts(call: Callable[..., object], seen: set[int]) -> Iterator[object]:
    if isinstance(call, _InjectDependency):
        yield call.contract
        return
    if id(call) in seen:
        return
    seen.add(id(call))
    for parameter in _dependency_parameters(call):
        annotation = parameter.annotation
        markers = []
        if get_origin(annotation) is Annotated:
            annotation, *metadata = get_args(annotation)
            markers.extend(value for value in metadata if isinstance(value, DependsMarker))
        if isinstance(parameter.default, DependsMarker):
            markers.append(parameter.default)
        for marker in markers:
            dependency = marker.dependency
            if dependency is None and isinstance(annotation, type):
                dependency = annotation
            if dependency is not None:
                yield from _collect_contracts(dependency, seen)


__all__ = ["CONTAINER_STATE_KEY", "FastAPIIntegration", "Inject"]
