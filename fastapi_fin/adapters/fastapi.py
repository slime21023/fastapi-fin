"""Native FastAPI dependencies backed by the active Dishka request scope."""

from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Mapping
from contextlib import asynccontextmanager
from inspect import Parameter, signature, unwrap
from itertools import chain
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Final, get_args, get_origin

from attrs import frozen
from dishka import AsyncContainer, BaseScope, Scope
from fastapi import Depends, FastAPI, Request, routing
from fastapi.params import Depends as DependsMarker
from fastapi.routing import APIRoute, APIWebSocketRoute

from .._validation import Contract, ModuleName, normalize_contract
from ..container import open_container
from ..errors import AdapterError, AssemblyError, DefinitionError
from ..modules import Application

CONTAINER_STATE_KEY: Final = "fastapi_fin_container"
_REQUEST_STATE_KEY: Final = "_fastapi_fin_request_container"
_FASTAPI_CONTEXT: Final[Mapping[Contract, BaseScope]] = MappingProxyType({Request: Scope.REQUEST})

# An endpoint, a FastAPI dependency, or a class used as one.
type DependencyCall = Callable[..., object]


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


@frozen
class _InjectDependency:
    contract: Contract

    async def __call__(
        self, container: Annotated[AsyncContainer, Depends(_request_container)]
    ) -> object:
        return await container.get(self.contract)


if TYPE_CHECKING:
    type Inject[T] = T
else:

    class Inject:
        """Declare an exported contract as a native FastAPI dependency."""

        def __class_getitem__(cls, contract: Contract) -> object:
            try:
                normalize_contract(contract)
            except DefinitionError as error:
                raise AdapterError(
                    "Inject contract must be a hashable type hint, not a string"
                ) from error
            return Annotated[contract, Depends(_InjectDependency(contract))]


@frozen
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


@frozen
class _RouteView:
    """The parts of a FastAPI route that can declare injected dependencies."""

    path: str
    calls: tuple[DependencyCall, ...]
    is_websocket: bool


def _validate_injections(app: FastAPI, exports: Mapping[Contract, ModuleName]) -> None:
    """Fail at startup when a route injects a contract that no module exports."""
    for route, contract in _injections(app):
        if route.is_websocket:
            raise AdapterError(f"Inject is not supported on WebSocket route {route.path!r}")
        if contract not in exports:
            raise AssemblyError(
                f"route {route.path!r} injects {contract!r}, which is not an exported contract"
            )


def _injections(app: FastAPI) -> Iterator[tuple[_RouteView, Contract]]:
    """Yield one ``(route, contract)`` pair per ``Inject`` found on the application's routes."""
    return chain.from_iterable(map(_route_injections, _iter_route_views(app)))


def _route_injections(route: _RouteView) -> Iterator[tuple[_RouteView, Contract]]:
    return ((route, contract) for contract in _injected_contracts(route))


def _iter_route_views(app: FastAPI) -> Iterator[_RouteView]:
    # Newer FastAPI versions expose included routes through route contexts.
    iter_contexts = getattr(routing, "iter_route_contexts", None)
    candidates = iter_contexts(app.routes) if iter_contexts is not None else app.routes
    for candidate in candidates:
        route = getattr(candidate, "original_route", candidate)
        if not isinstance(route, APIRoute | APIWebSocketRoute):
            continue
        yield _RouteView(
            path=getattr(candidate, "path", route.path),
            calls=_route_calls(
                getattr(candidate, "endpoint", route.endpoint),
                getattr(candidate, "dependencies", route.dependencies),
            ),
            is_websocket=isinstance(route, APIWebSocketRoute),
        )


def _route_calls(
    endpoint: DependencyCall, dependencies: Iterable[DependsMarker]
) -> tuple[DependencyCall, ...]:
    """The endpoint plus every route-level dependency callable."""
    return (
        endpoint,
        *(marker.dependency for marker in dependencies if marker.dependency is not None),
    )


def _injected_contracts(route: _RouteView) -> Iterator[Contract]:
    visited: set[int] = set()
    return chain.from_iterable(_collect_contracts(call, visited) for call in route.calls)


def _collect_contracts(call: DependencyCall, visited: set[int]) -> Iterator[Contract]:
    """Yield every contract injected by ``call`` or by its nested FastAPI dependencies."""
    if isinstance(call, _InjectDependency):
        yield call.contract
        return
    if id(call) in visited:
        return
    visited.add(id(call))
    nested = chain.from_iterable(map(_parameter_dependencies, _dependency_parameters(call)))
    for dependency in nested:
        yield from _collect_contracts(dependency, visited)


def _parameter_dependencies(parameter: Parameter) -> Iterator[DependencyCall]:
    """Yield the callables behind ``Annotated[..., Depends(...)]`` or ``= Depends(...)``."""
    annotation = parameter.annotation
    markers: list[DependsMarker] = []
    if get_origin(annotation) is Annotated:
        annotation, *metadata = get_args(annotation)
        markers.extend(item for item in metadata if isinstance(item, DependsMarker))
    if isinstance(parameter.default, DependsMarker):
        markers.append(parameter.default)
    for marker in markers:
        # ``Depends()`` without a callable means "call the annotated class".
        dependency = marker.dependency
        if dependency is None and isinstance(annotation, type):
            dependency = annotation
        if dependency is not None:
            yield dependency


def _dependency_parameters(call: DependencyCall) -> Iterable[Parameter]:
    try:
        return signature(call, eval_str=True, globals=_annotation_globals(call)).parameters.values()
    except (NameError, TypeError, ValueError, SyntaxError):
        # FastAPI may accept annotations that inspect cannot resolve.
        try:
            return signature(call).parameters.values()
        except (TypeError, ValueError):
            return ()


def _annotation_globals(call: DependencyCall) -> dict[str, object] | None:
    """Locate the namespace where ``call``'s string annotations were written."""
    target = unwrap(call)
    if isinstance(target, type):
        target = target.__init__
    elif not hasattr(target, "__globals__"):
        target = type(target).__call__
    return getattr(target, "__globals__", None)


__all__ = ["CONTAINER_STATE_KEY", "FastAPIIntegration", "Inject"]
