"""Immutable route and controller metadata shared by all Adapters."""

from collections.abc import Callable, Iterable
from typing import Final

from attrs import evolve, field, frozen, validators

from ..errors import DeclarationError, RegistrationError
from ..guard import GuardPolicy, GuardRule
from ..interceptor import InterceptorChain, InterceptorSpec
from ..types import (
    HttpMethod,
    _validate_nonnegative_integer,
    join_paths,
    normalize_methods,
    normalize_path,
)

Endpoint = Callable[..., object]
ControllerType = type[object]

_ROUTE_METADATA_ATTRIBUTE: Final[str] = "__fastapi_fin_route_metadata__"
_CONTROLLER_METADATA_ATTRIBUTE: Final[str] = "__fastapi_fin_controller_metadata__"
_MODULE_METADATA_ATTRIBUTE: Final[str] = "__fastapi_fin_module_metadata__"
_UNSET_RESPONSE_MODEL: Final[object] = object()


def _normalize_name(name: str) -> str:
    if not isinstance(name, str):
        raise DeclarationError("metadata name must be a string")
    normalized = name.strip()
    if not normalized:
        raise DeclarationError("metadata name must not be empty")
    return normalized


def _normalize_optional_text(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise DeclarationError("route text metadata must be a string or None")
    normalized = value.strip()
    if not normalized:
        raise DeclarationError("route text metadata must not be empty")
    return normalized


def _normalize_status_code(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
        raise DeclarationError("route status_code must be an integer between 100 and 599")
    return value


def _normalize_tags(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    try:
        normalized_values = tuple(values)
    except TypeError as error:
        raise DeclarationError("route tags must be iterable") from error

    tags: list[str] = []
    for value in normalized_values:
        if not isinstance(value, str):
            raise DeclarationError("route tags must contain strings")
        tag = value.strip()
        if not tag:
            raise DeclarationError("route tags must not contain empty strings")
        if tag not in tags:
            tags.append(tag)
    return tuple(tags)


def _validate_guard_rules(
    _instance: object,
    _attribute: object,
    rules: tuple[GuardRule, ...],
) -> None:
    GuardPolicy(rules=rules)


def _normalize_guards(values: Iterable[GuardRule]) -> tuple[GuardRule, ...]:
    try:
        normalized = tuple(values)
    except TypeError as error:
        raise DeclarationError("metadata guards must be iterable") from error
    GuardPolicy(rules=normalized)
    return normalized


def _validate_endpoint(_instance: object, _attribute: object, endpoint: Endpoint) -> None:
    if not callable(endpoint):
        raise DeclarationError("route endpoint must be callable")


def _normalize_interceptors(
    values: Iterable[InterceptorSpec],
) -> tuple[InterceptorSpec, ...]:
    try:
        normalized = tuple(values)
    except TypeError as error:
        raise DeclarationError("metadata interceptors must be iterable") from error
    if not all(isinstance(interceptor, InterceptorSpec) for interceptor in normalized):
        raise DeclarationError("metadata interceptors must be InterceptorSpec instances")
    return InterceptorChain(interceptors=normalized).interceptors


def _routes_conflict(left: "RouteMetadata", right: "RouteMetadata") -> bool:
    return left.path == right.path and bool(set(left.methods) & set(right.methods))


@frozen(slots=True, kw_only=True)
class RouteMetadata:
    """Immutable description of one endpoint declaration."""

    path: str = field(converter=normalize_path)
    methods: tuple[HttpMethod, ...] = field(converter=normalize_methods)
    endpoint: Endpoint = field(validator=_validate_endpoint)
    name: str = field(converter=_normalize_name)
    deprecated: bool = field(default=False, validator=validators.instance_of(bool))
    internal: bool = field(default=False, validator=validators.instance_of(bool))
    response_model: object = field(default=_UNSET_RESPONSE_MODEL, repr=False)
    status_code: int | None = field(default=None, converter=_normalize_status_code)
    tags: tuple[str, ...] = field(factory=tuple, converter=_normalize_tags)
    summary: str | None = field(default=None, converter=_normalize_optional_text)
    description: str | None = field(default=None, converter=_normalize_optional_text)
    response_description: str | None = field(
        default=None,
        converter=_normalize_optional_text,
    )
    operation_id: str | None = field(default=None, converter=_normalize_optional_text)
    guards: tuple[GuardRule, ...] = field(
        factory=tuple,
        converter=_normalize_guards,
        validator=_validate_guard_rules,
    )
    interceptors: tuple[InterceptorSpec, ...] = field(
        factory=tuple,
        converter=_normalize_interceptors,
    )

    def with_prefix(self, prefix: str) -> "RouteMetadata":
        """Return a new route with a module/controller prefix applied."""
        return evolve(self, path=join_paths(prefix, self.path))

    @property
    def has_response_model(self) -> bool:
        """Whether the declaration explicitly supplied a response model."""
        return self.response_model is not _UNSET_RESPONSE_MODEL


def _normalize_routes(values: Iterable[RouteMetadata]) -> tuple[RouteMetadata, ...]:
    try:
        normalized = tuple(values)
    except TypeError as error:
        raise DeclarationError("metadata routes must be iterable") from error
    if not all(isinstance(route, RouteMetadata) for route in normalized):
        raise DeclarationError("metadata routes must be RouteMetadata instances")
    return normalized


@frozen(slots=True, kw_only=True)
class ControllerMetadata:
    """Immutable description of a controller and its final route paths."""

    controller: ControllerType = field(validator=validators.instance_of(type))
    prefix: str = field(converter=normalize_path)
    routes: tuple[RouteMetadata, ...] = field(converter=_normalize_routes)
    name: str = field(converter=_normalize_name)


def _normalize_controllers(
    values: Iterable[ControllerMetadata],
) -> tuple[ControllerMetadata, ...]:
    try:
        normalized = tuple(values)
    except TypeError as error:
        raise DeclarationError("metadata controllers must be iterable") from error
    if not all(isinstance(controller, ControllerMetadata) for controller in normalized):
        raise DeclarationError("metadata controllers must be ControllerMetadata instances")
    return normalized


def _normalize_modules(values: Iterable["ModuleMetadata"]) -> tuple["ModuleMetadata", ...]:
    try:
        normalized = tuple(values)
    except TypeError as error:
        raise DeclarationError("metadata modules must be iterable") from error
    if not all(isinstance(module, ModuleMetadata) for module in normalized):
        raise DeclarationError("metadata modules must be ModuleMetadata instances")
    return normalized


@frozen(slots=True, kw_only=True)
class ModuleMetadata:
    """Immutable module composition tree."""

    name: str = field(converter=_normalize_name)
    prefix: str = field(default="/", converter=normalize_path)
    controllers: tuple[ControllerMetadata, ...] = field(
        factory=tuple,
        converter=_normalize_controllers,
    )
    modules: tuple["ModuleMetadata", ...] = field(
        factory=tuple,
        converter=_normalize_modules,
    )
    guards: tuple[GuardRule, ...] = field(
        factory=tuple,
        converter=_normalize_guards,
        validator=_validate_guard_rules,
    )
    interceptors: tuple[InterceptorSpec, ...] = field(
        factory=tuple,
        converter=_normalize_interceptors,
    )

    def flatten_controllers(
        self,
        *,
        parent_prefix: str = "/",
        parent_guards: tuple[GuardRule, ...] = (),
        parent_interceptors: tuple[InterceptorSpec, ...] = (),
    ) -> tuple[ControllerMetadata, ...]:
        """Return final controller metadata in deterministic composition order."""
        prefix = join_paths(parent_prefix, self.prefix)
        guards = (*parent_guards, *self.guards)
        interceptors = (*parent_interceptors, *self.interceptors)
        GuardPolicy(rules=guards)

        flattened: list[ControllerMetadata] = []
        for controller in self.controllers:
            routes: list[RouteMetadata] = []
            for route in controller.routes:
                effective_route = evolve(
                    route.with_prefix(prefix),
                    guards=(*guards, *route.guards),
                    interceptors=(*interceptors, *route.interceptors),
                )
                InterceptorChain(interceptors=effective_route.interceptors)
                routes.append(effective_route)
            flattened.append(
                evolve(
                    controller,
                    prefix=join_paths(prefix, controller.prefix),
                    routes=tuple(routes),
                )
            )

        for module in self.modules:
            flattened.extend(
                module.flatten_controllers(
                    parent_prefix=prefix,
                    parent_guards=guards,
                    parent_interceptors=interceptors,
                )
            )
        return tuple(flattened)


@frozen(slots=True, kw_only=True)
class MetadataSnapshot:
    """Versioned immutable collection of registered controllers."""

    controllers: tuple[ControllerMetadata, ...] = field(
        factory=tuple,
        converter=_normalize_controllers,
    )
    version: int = field(default=0, validator=_validate_nonnegative_integer)

    def register(self, controller: ControllerMetadata) -> "MetadataSnapshot":
        """Return a new snapshot after registering one controller."""
        if not isinstance(controller, ControllerMetadata):
            raise RegistrationError("controller must be a ControllerMetadata instance")
        registered_routes = [route for current in self.controllers for route in current.routes]
        for route in controller.routes:
            InterceptorChain(interceptors=route.interceptors)
            if any(_routes_conflict(route, registered) for registered in registered_routes):
                raise RegistrationError(
                    f"duplicate route registration for {route.methods!r} {route.path!r}"
                )
            registered_routes.append(route)

        return evolve(
            self,
            controllers=(*self.controllers, controller),
            version=self.version + 1,
        )

    @property
    def routes(self) -> tuple[RouteMetadata, ...]:
        """Return all registered routes in declaration order."""
        return tuple(route for controller in self.controllers for route in controller.routes)


def collect_controller_metadata(
    controller: ControllerType,
    *,
    prefix: str = "/",
    name: str | None = None,
) -> ControllerMetadata:
    """Collect decorated endpoint metadata from a controller class."""
    normalized_prefix = normalize_path(prefix)
    routes: list[RouteMetadata] = []
    for attribute_name, attribute in vars(controller).items():
        endpoint = _unwrap_descriptor(attribute)
        metadata = getattr(endpoint, _ROUTE_METADATA_ATTRIBUTE, None)
        if not isinstance(metadata, RouteMetadata):
            continue
        route_name = metadata.name or attribute_name
        routes.append(evolve(metadata, name=route_name).with_prefix(normalized_prefix))

    controller_name = controller.__name__ if name is None else name
    return ControllerMetadata(
        controller=controller,
        prefix=normalized_prefix,
        routes=tuple(routes),
        name=controller_name,
    )


def attach_route_metadata(endpoint: Endpoint, metadata: RouteMetadata) -> Endpoint:
    """Attach immutable route metadata to a user endpoint."""
    setattr(endpoint, _ROUTE_METADATA_ATTRIBUTE, metadata)
    return endpoint


def attach_controller_metadata(
    controller: ControllerType,
    metadata: ControllerMetadata,
) -> ControllerType:
    """Attach immutable controller metadata to a user controller class."""
    setattr(controller, _CONTROLLER_METADATA_ATTRIBUTE, metadata)
    return controller


def attach_module_metadata(
    module: type[object],
    metadata: ModuleMetadata,
) -> type[object]:
    """Attach immutable module metadata to a module declaration class."""
    setattr(module, _MODULE_METADATA_ATTRIBUTE, metadata)
    return module


def get_controller_metadata(value: object) -> ControllerMetadata:
    """Read metadata attached by the controller decorator."""
    metadata = getattr(value, _CONTROLLER_METADATA_ATTRIBUTE, None)
    if not isinstance(metadata, ControllerMetadata):
        raise DeclarationError("value is not decorated with @controller")
    return metadata


def get_module_metadata(value: object) -> ModuleMetadata:
    """Read metadata attached by the module decorator."""
    metadata = getattr(value, _MODULE_METADATA_ATTRIBUTE, None)
    if not isinstance(metadata, ModuleMetadata):
        raise DeclarationError("value is not decorated with @module")
    return metadata


def _unwrap_descriptor(value: object) -> object:
    if isinstance(value, (staticmethod, classmethod)):
        return value.__func__
    return value


def get_route_metadata(value: object) -> RouteMetadata:
    """Read metadata attached by an HTTP method decorator."""
    metadata = getattr(value, _ROUTE_METADATA_ATTRIBUTE, None)
    if not isinstance(metadata, RouteMetadata):
        raise DeclarationError("value is not decorated with a route decorator")
    return metadata
