"""Framework-independent compilation of metadata into executable routes."""

from collections.abc import Callable, Iterable

from attrs import evolve, field, frozen, validators

from ..core.errors import DeclarationError
from ..core.guard import GuardPolicy, GuardRule
from ..core.interceptor import InterceptorChain, InterceptorSpec
from ..core.metadata import ControllerMetadata, Endpoint, RouteMetadata
from ..core.types import _validate_nonnegative_integer
from .registry import ApplicationRegistry

EndpointResolver = Callable[[ControllerMetadata, RouteMetadata], Endpoint]


def _validate_endpoint(_instance: object, _attribute: object, endpoint: Endpoint) -> None:
    if not callable(endpoint):
        raise DeclarationError("compiled route endpoint must be callable")


def _normalize_routes(values: Iterable["CompiledRoute"]) -> tuple["CompiledRoute", ...]:
    try:
        normalized = tuple(values)
    except TypeError as error:
        raise DeclarationError("compiled application routes must be iterable") from error
    if not all(isinstance(route, CompiledRoute) for route in normalized):
        raise DeclarationError("compiled application routes must be CompiledRoute instances")
    return normalized


@frozen(slots=True, kw_only=True)
class CompiledRoute:
    """Immutable executable route produced from framework-independent metadata."""

    controller: ControllerMetadata = field(
        validator=validators.instance_of(ControllerMetadata),
    )
    metadata: RouteMetadata = field(validator=validators.instance_of(RouteMetadata))
    endpoint: Endpoint = field(validator=_validate_endpoint)


@frozen(slots=True, kw_only=True)
class CompiledApplication:
    """Immutable route compilation result for one application metadata snapshot."""

    routes: tuple[CompiledRoute, ...] = field(
        factory=tuple,
        converter=_normalize_routes,
    )
    metadata_version: int = field(default=0, validator=_validate_nonnegative_integer)


def compile_application(
    registry: ApplicationRegistry,
    *,
    endpoint_resolver: EndpointResolver,
    global_guards: Iterable[GuardRule] = (),
    global_interceptors: Iterable[InterceptorSpec] = (),
) -> CompiledApplication:
    """Compile a registry snapshot without importing or constructing FastAPI objects.

    ``endpoint_resolver`` is supplied by the boundary adapter because resolving a
    controller may be framework-specific. The compiler owns immutable route
    composition and validates all global/per-route policy combinations before the
    adapter receives the result.
    """
    if not callable(endpoint_resolver):
        raise DeclarationError("endpoint_resolver must be callable")

    try:
        normalized_guards = tuple(global_guards)
        normalized_interceptors = tuple(global_interceptors)
    except TypeError as error:
        raise DeclarationError("global policies must be iterable") from error
    GuardPolicy(rules=normalized_guards)
    InterceptorChain(interceptors=normalized_interceptors)

    compiled_routes: list[CompiledRoute] = []
    for controller in registry.metadata.controllers:
        for route in controller.routes:
            effective_route = route
            if normalized_guards or normalized_interceptors:
                effective_route = evolve(
                    route,
                    guards=(*normalized_guards, *route.guards),
                    interceptors=(*normalized_interceptors, *route.interceptors),
                )

            endpoint = endpoint_resolver(controller, effective_route)
            compiled_routes.append(
                CompiledRoute(
                    controller=controller,
                    metadata=effective_route,
                    endpoint=endpoint,
                )
            )

    return CompiledApplication(
        routes=tuple(compiled_routes),
        metadata_version=registry.metadata.version,
    )
