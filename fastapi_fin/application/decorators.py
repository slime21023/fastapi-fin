"""Framework-independent decorators for route declarations."""

from collections.abc import Callable, Iterable
from typing import ParamSpec, TypeVar

from attrs import evolve

from ..core.errors import DeclarationError
from ..core.guard import GuardRule
from ..core.interceptor import InterceptorSpec
from ..core.metadata import (
    _UNSET_RESPONSE_MODEL,
    ModuleMetadata,
    RouteMetadata,
    attach_controller_metadata,
    attach_module_metadata,
    attach_route_metadata,
    collect_controller_metadata,
    get_controller_metadata,
    get_module_metadata,
    get_route_metadata,
)
from ..core.types import HttpMethod, normalize_methods

P = ParamSpec("P")
R = TypeVar("R")
C = TypeVar("C")
M = TypeVar("M")


def _normalize_iterable[T](values: Iterable[T], label: str) -> tuple[T, ...]:
    try:
        return tuple(values)
    except TypeError as error:
        raise DeclarationError(f"{label} must be iterable") from error


def route(
    path: str,
    *,
    methods: str | HttpMethod | Iterable[str | HttpMethod],
    name: str | None = None,
    deprecated: bool = False,
    internal: bool = False,
    response_model: object = _UNSET_RESPONSE_MODEL,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare an endpoint route without importing FastAPI."""
    normalized_methods = normalize_methods(methods)

    def decorator(endpoint: Callable[P, R]) -> Callable[P, R]:
        metadata = RouteMetadata(
            path=path,
            methods=normalized_methods,
            endpoint=endpoint,
            name=(
                str(getattr(endpoint, "__name__", type(endpoint).__name__))
                if name is None
                else name
            ),
            deprecated=deprecated,
            internal=internal,
            response_model=response_model,
            status_code=status_code,
            tags=tags,
            summary=summary,
            description=description,
            response_description=response_description,
            operation_id=operation_id,
        )
        attach_route_metadata(endpoint, metadata)
        return endpoint

    return decorator


def get(
    path: str,
    *,
    name: str | None = None,
    deprecated: bool = False,
    internal: bool = False,
    response_model: object = _UNSET_RESPONSE_MODEL,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a GET endpoint."""
    return _method_route(
        HttpMethod.GET,
        path,
        name=name,
        deprecated=deprecated,
        internal=internal,
        response_model=response_model,
        status_code=status_code,
        tags=tags,
        summary=summary,
        description=description,
        response_description=response_description,
        operation_id=operation_id,
    )


def post(
    path: str,
    *,
    name: str | None = None,
    deprecated: bool = False,
    internal: bool = False,
    response_model: object = _UNSET_RESPONSE_MODEL,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a POST endpoint."""
    return _method_route(
        HttpMethod.POST,
        path,
        name=name,
        deprecated=deprecated,
        internal=internal,
        response_model=response_model,
        status_code=status_code,
        tags=tags,
        summary=summary,
        description=description,
        response_description=response_description,
        operation_id=operation_id,
    )


def delete(
    path: str,
    *,
    name: str | None = None,
    deprecated: bool = False,
    internal: bool = False,
    response_model: object = _UNSET_RESPONSE_MODEL,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a DELETE endpoint."""
    return _method_route(
        HttpMethod.DELETE,
        path,
        name=name,
        deprecated=deprecated,
        internal=internal,
        response_model=response_model,
        status_code=status_code,
        tags=tags,
        summary=summary,
        description=description,
        response_description=response_description,
        operation_id=operation_id,
    )


def put(
    path: str,
    *,
    name: str | None = None,
    deprecated: bool = False,
    internal: bool = False,
    response_model: object = _UNSET_RESPONSE_MODEL,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a PUT endpoint."""
    return _method_route(
        HttpMethod.PUT,
        path,
        name=name,
        deprecated=deprecated,
        internal=internal,
        response_model=response_model,
        status_code=status_code,
        tags=tags,
        summary=summary,
        description=description,
        response_description=response_description,
        operation_id=operation_id,
    )


def patch(
    path: str,
    *,
    name: str | None = None,
    deprecated: bool = False,
    internal: bool = False,
    response_model: object = _UNSET_RESPONSE_MODEL,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a PATCH endpoint."""
    return _method_route(
        HttpMethod.PATCH,
        path,
        name=name,
        deprecated=deprecated,
        internal=internal,
        response_model=response_model,
        status_code=status_code,
        tags=tags,
        summary=summary,
        description=description,
        response_description=response_description,
        operation_id=operation_id,
    )


def options(
    path: str,
    *,
    name: str | None = None,
    deprecated: bool = False,
    internal: bool = False,
    response_model: object = _UNSET_RESPONSE_MODEL,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare an OPTIONS endpoint."""
    return _method_route(
        HttpMethod.OPTIONS,
        path,
        name=name,
        deprecated=deprecated,
        internal=internal,
        response_model=response_model,
        status_code=status_code,
        tags=tags,
        summary=summary,
        description=description,
        response_description=response_description,
        operation_id=operation_id,
    )


def head(
    path: str,
    *,
    name: str | None = None,
    deprecated: bool = False,
    internal: bool = False,
    response_model: object = _UNSET_RESPONSE_MODEL,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a HEAD endpoint."""
    return _method_route(
        HttpMethod.HEAD,
        path,
        name=name,
        deprecated=deprecated,
        internal=internal,
        response_model=response_model,
        status_code=status_code,
        tags=tags,
        summary=summary,
        description=description,
        response_description=response_description,
        operation_id=operation_id,
    )


def connect(
    path: str,
    *,
    name: str | None = None,
    deprecated: bool = False,
    internal: bool = False,
    response_model: object = _UNSET_RESPONSE_MODEL,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a CONNECT endpoint."""
    return _method_route(
        HttpMethod.CONNECT,
        path,
        name=name,
        deprecated=deprecated,
        internal=internal,
        response_model=response_model,
        status_code=status_code,
        tags=tags,
        summary=summary,
        description=description,
        response_description=response_description,
        operation_id=operation_id,
    )


def trace(
    path: str,
    *,
    name: str | None = None,
    deprecated: bool = False,
    internal: bool = False,
    response_model: object = _UNSET_RESPONSE_MODEL,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Declare a TRACE endpoint."""
    return _method_route(
        HttpMethod.TRACE,
        path,
        name=name,
        deprecated=deprecated,
        internal=internal,
        response_model=response_model,
        status_code=status_code,
        tags=tags,
        summary=summary,
        description=description,
        response_description=response_description,
        operation_id=operation_id,
    )


def _method_route(
    method: HttpMethod,
    path: str,
    *,
    name: str | None,
    deprecated: bool,
    internal: bool,
    response_model: object,
    status_code: int | None,
    tags: Iterable[str],
    summary: str | None,
    description: str | None,
    response_description: str | None,
    operation_id: str | None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    return route(
        path,
        methods=method,
        name=name,
        deprecated=deprecated,
        internal=internal,
        response_model=response_model,
        status_code=status_code,
        tags=tags,
        summary=summary,
        description=description,
        response_description=response_description,
        operation_id=operation_id,
    )


def controller(
    prefix: str = "/",
    *,
    name: str | None = None,
    guards: Iterable[GuardRule] = (),
    interceptors: Iterable[InterceptorSpec] = (),
) -> Callable[[type[C]], type[C]]:
    """Collect route declarations from a controller class."""

    def decorator(controller_type: type[C]) -> type[C]:
        metadata = collect_controller_metadata(
            controller_type,
            prefix=prefix,
            name=name,
        )
        controller_guards = _normalize_iterable(guards, "controller guards")
        controller_interceptors = _normalize_iterable(
            interceptors,
            "controller interceptors",
        )
        metadata = evolve(
            metadata,
            routes=tuple(
                evolve(
                    route_metadata,
                    guards=(*controller_guards, *route_metadata.guards),
                    interceptors=(*controller_interceptors, *route_metadata.interceptors),
                )
                for route_metadata in metadata.routes
            ),
        )
        attach_controller_metadata(controller_type, metadata)
        return controller_type

    return decorator


def module(
    name: str | None = None,
    *,
    prefix: str = "/",
    controllers: Iterable[type[object]] = (),
    modules: Iterable[type[object]] = (),
    guards: Iterable[GuardRule] = (),
    interceptors: Iterable[InterceptorSpec] = (),
) -> Callable[[type[M]], type[M]]:
    """Declare an immutable module composition boundary."""

    def decorator(module_type: type[M]) -> type[M]:
        controller_types = _normalize_iterable(controllers, "module controllers")
        child_module_types = _normalize_iterable(modules, "module modules")
        module_guards = _normalize_iterable(guards, "module guards")
        module_interceptors = _normalize_iterable(interceptors, "module interceptors")
        controller_metadata = tuple(
            get_controller_metadata(controller) for controller in controller_types
        )
        module_metadata = tuple(
            get_module_metadata(child_module) for child_module in child_module_types
        )
        metadata = ModuleMetadata(
            name=module_type.__name__ if name is None else name,
            prefix=prefix,
            controllers=controller_metadata,
            modules=module_metadata,
            guards=module_guards,
            interceptors=module_interceptors,
        )
        attach_module_metadata(module_type, metadata)
        return module_type

    return decorator


def guard(rule: GuardRule) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Attach one authorization rule to an endpoint declaration."""

    def decorator(endpoint: Callable[P, R]) -> Callable[P, R]:
        metadata = get_route_metadata(endpoint)
        attach_route_metadata(endpoint, evolve(metadata, guards=(*metadata.guards, rule)))
        return endpoint

    return decorator


def use_interceptor(
    interceptor: InterceptorSpec,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Attach one interceptor to an endpoint declaration."""

    def decorator(endpoint: Callable[P, R]) -> Callable[P, R]:
        metadata = get_route_metadata(endpoint)
        attach_route_metadata(
            endpoint,
            evolve(metadata, interceptors=(*metadata.interceptors, interceptor)),
        )
        return endpoint

    return decorator
