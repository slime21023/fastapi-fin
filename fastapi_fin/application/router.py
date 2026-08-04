"""Framework-independent, FastAPI-like route grouping."""

from collections.abc import Callable, Iterable
from typing import Any, TypeVar

from attrs import define, evolve, field

from .._validation import normalize_iterable
from ..errors import DefinitionError
from ..features.guards import GuardDefinition
from ..features.interceptors import InterceptorDefinition
from .definitions import (
    Endpoint,
    HttpMethod,
    RouteDefinition,
    route,
)

EndpointT = TypeVar("EndpointT", bound=Endpoint)


def _normalize_prefix(prefix: str) -> str:
    if not isinstance(prefix, str):
        raise DefinitionError("router prefix must be a string")
    value = prefix.strip()
    if not value or value == "/":
        return ""
    if any(character.isspace() for character in value) or "?" in value or "#" in value:
        raise DefinitionError(f"invalid router prefix: {prefix!r}")
    if "\x00" in value:
        raise DefinitionError("router prefix must not contain a null character")
    return "/" + value.strip("/")


def _normalize_tags(values: Iterable[str], label: str) -> tuple[str, ...]:
    if isinstance(values, str):
        raise DefinitionError(f"{label} must be an iterable of strings")
    normalized = normalize_iterable(values, label)
    if not all(isinstance(value, str) and value.strip() for value in normalized):
        raise DefinitionError(f"{label} must contain non-empty strings")
    return normalized


def _normalize_guards(
    values: Iterable[GuardDefinition],
    label: str,
) -> tuple[GuardDefinition, ...]:
    normalized = normalize_iterable(values, label)
    if not all(isinstance(value, GuardDefinition) for value in normalized):
        raise DefinitionError(f"{label} must contain GuardDefinition values")
    return normalized


def _normalize_interceptors(
    values: Iterable[InterceptorDefinition],
    label: str,
) -> tuple[InterceptorDefinition, ...]:
    normalized = normalize_iterable(values, label)
    if not all(isinstance(value, InterceptorDefinition) for value in normalized):
        raise DefinitionError(f"{label} must contain InterceptorDefinition values")
    return normalized


def _join_paths(*parts: str) -> str:
    if not all(isinstance(part, str) for part in parts):
        raise DefinitionError("router paths must be strings")
    non_empty = tuple(part.strip() for part in parts if part.strip())
    if not non_empty:
        return "/"
    segments = tuple(part.strip("/") for part in non_empty if part.strip("/"))
    value = "/" + "/".join(segments)
    if non_empty[-1].endswith("/") and value != "/":
        value += "/"
    return value


@define(slots=True, eq=False)
class ApplicationRouter:
    """Declaration-time route builder with FastAPI-like decorators.

    The builder may collect routes while a module is imported. Its routes can be
    passed directly to ``ApplicationDefinition``; ``snapshot`` remains available
    for explicit low-level inspection and composition.
    """

    prefix: str = field(default="", converter=_normalize_prefix)
    tags: tuple[str, ...] = field(
        default=(),
        converter=lambda value: _normalize_tags(value, "router tags"),
    )
    guards: tuple[GuardDefinition, ...] = field(
        default=(),
        converter=lambda value: _normalize_guards(value, "router guards"),
    )
    interceptors: tuple[InterceptorDefinition, ...] = field(
        default=(),
        converter=lambda value: _normalize_interceptors(value, "router interceptors"),
    )
    _routes: list[RouteDefinition] = field(factory=list, init=False, repr=False)

    @property
    def routes(self) -> tuple[RouteDefinition, ...]:
        """Return the current immutable route snapshot."""
        return self.snapshot()

    def snapshot(self) -> tuple[RouteDefinition, ...]:
        """Return routes collected so far as an immutable tuple."""
        return tuple(self._routes)

    def add_api_route(
        self,
        path: str,
        endpoint: Endpoint,
        *,
        methods: str | HttpMethod | Iterable[str | HttpMethod] = HttpMethod.GET,
        name: str | None = None,
        deprecated: bool = False,
        include_in_schema: bool = True,
        response_model: object | None = None,
        status_code: int | None = None,
        tags: Iterable[str] = (),
        summary: str | None = None,
        description: str | None = None,
        response_description: str | None = None,
        operation_id: str | None = None,
        guards: Iterable[GuardDefinition] = (),
        interceptors: Iterable[InterceptorDefinition] = (),
    ) -> None:
        """Register one route during application declaration."""
        if not isinstance(path, str) or not path.strip():
            raise DefinitionError("route path must not be empty")
        route_tags = _normalize_tags(tags, "route tags")
        route_guards = _normalize_guards(guards, "route guards")
        route_interceptors = _normalize_interceptors(interceptors, "route interceptors")
        self._routes.append(
            route(
                _join_paths(self.prefix, path),
                endpoint,
                methods=methods,
                name=name,
                deprecated=deprecated,
                include_in_schema=include_in_schema,
                response_model=response_model,
                status_code=status_code,
                tags=(*self.tags, *route_tags),
                summary=summary,
                description=description,
                response_description=response_description,
                operation_id=operation_id,
                guards=(*self.guards, *route_guards),
                interceptors=(*self.interceptors, *route_interceptors),
            ),
        )

    def api_route(
        self,
        path: str,
        *,
        methods: str | HttpMethod | Iterable[str | HttpMethod] = HttpMethod.GET,
        name: str | None = None,
        deprecated: bool = False,
        include_in_schema: bool = True,
        response_model: object | None = None,
        status_code: int | None = None,
        tags: Iterable[str] = (),
        summary: str | None = None,
        description: str | None = None,
        response_description: str | None = None,
        operation_id: str | None = None,
        guards: Iterable[GuardDefinition] = (),
        interceptors: Iterable[InterceptorDefinition] = (),
    ) -> Callable[[EndpointT], EndpointT]:
        """Return a decorator that registers a route and preserves the endpoint."""

        def decorator(endpoint: EndpointT) -> EndpointT:
            self.add_api_route(
                path,
                endpoint,
                methods=methods,
                name=name,
                deprecated=deprecated,
                include_in_schema=include_in_schema,
                response_model=response_model,
                status_code=status_code,
                tags=tags,
                summary=summary,
                description=description,
                response_description=response_description,
                operation_id=operation_id,
                guards=guards,
                interceptors=interceptors,
            )
            return endpoint

        return decorator

    def _method_decorator(
        self,
        path: str,
        method: HttpMethod,
        options: dict[str, Any],
    ) -> Callable[[EndpointT], EndpointT]:
        return self.api_route(path, methods=method, **options)

    def get(self, path: str, **options: Any) -> Callable[[EndpointT], EndpointT]:
        """Register a GET route with decorator syntax."""
        return self._method_decorator(path, HttpMethod.GET, options)

    def post(self, path: str, **options: Any) -> Callable[[EndpointT], EndpointT]:
        """Register a POST route with decorator syntax."""
        return self._method_decorator(path, HttpMethod.POST, options)

    def put(self, path: str, **options: Any) -> Callable[[EndpointT], EndpointT]:
        """Register a PUT route with decorator syntax."""
        return self._method_decorator(path, HttpMethod.PUT, options)

    def patch(self, path: str, **options: Any) -> Callable[[EndpointT], EndpointT]:
        """Register a PATCH route with decorator syntax."""
        return self._method_decorator(path, HttpMethod.PATCH, options)

    def delete(self, path: str, **options: Any) -> Callable[[EndpointT], EndpointT]:
        """Register a DELETE route with decorator syntax."""
        return self._method_decorator(path, HttpMethod.DELETE, options)

    def options(self, path: str, **options: Any) -> Callable[[EndpointT], EndpointT]:
        """Register an OPTIONS route with decorator syntax."""
        return self._method_decorator(path, HttpMethod.OPTIONS, options)

    def head(self, path: str, **options: Any) -> Callable[[EndpointT], EndpointT]:
        """Register a HEAD route with decorator syntax."""
        return self._method_decorator(path, HttpMethod.HEAD, options)

    def trace(self, path: str, **options: Any) -> Callable[[EndpointT], EndpointT]:
        """Register a TRACE route with decorator syntax."""
        return self._method_decorator(path, HttpMethod.TRACE, options)

    def connect(self, path: str, **options: Any) -> Callable[[EndpointT], EndpointT]:
        """Register a CONNECT route with decorator syntax."""
        return self._method_decorator(path, HttpMethod.CONNECT, options)

    def include_router(
        self,
        router: "ApplicationRouter",
        *,
        prefix: str = "",
        tags: Iterable[str] = (),
        guards: Iterable[GuardDefinition] = (),
        interceptors: Iterable[InterceptorDefinition] = (),
    ) -> None:
        """Include another router while preserving an immutable route snapshot."""
        if not isinstance(router, ApplicationRouter):
            raise DefinitionError("included router must be an ApplicationRouter")
        include_prefix = _normalize_prefix(prefix)
        include_tags = _normalize_tags(tags, "included router tags")
        include_guards = _normalize_guards(guards, "included router guards")
        include_interceptors = _normalize_interceptors(
            interceptors,
            "included router interceptors",
        )
        for route_definition in router.snapshot():
            self._routes.append(
                evolve(
                    route_definition,
                    path=_join_paths(self.prefix, include_prefix, route_definition.path),
                    tags=(*self.tags, *include_tags, *route_definition.tags),
                    guards=(*self.guards, *include_guards, *route_definition.guards),
                    interceptors=(
                        *self.interceptors,
                        *include_interceptors,
                        *route_definition.interceptors,
                    ),
                ),
            )


__all__ = ["ApplicationRouter"]
