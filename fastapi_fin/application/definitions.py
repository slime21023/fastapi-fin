"""Immutable, framework-independent application definitions."""

from collections.abc import Awaitable, Callable, Iterable
from enum import StrEnum
from typing import Any, TypeVar, cast

from attrs import define, field

from .._validation import (
    bool_validator,
    callable_validator,
    instance_validator,
    normalize_iterable,
    optional_callable_validator,
    optional_non_empty_text_validator,
)
from ..errors import DefinitionError
from ..features.guards import GuardDefinition
from ..features.interceptors import InterceptorDefinition

Endpoint = Callable[..., object]
ServiceToken = type[object] | str
ProviderFactory = Callable[..., object]
Disposer = Callable[[object], object | Awaitable[object]]
LifecycleHook = Callable[[], object | Awaitable[object]]
InjectedType = TypeVar("InjectedType")


class HttpMethod(StrEnum):
    """HTTP methods accepted by a route definition."""

    CONNECT = "CONNECT"
    DELETE = "DELETE"
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH = "PATCH"
    POST = "POST"
    PUT = "PUT"
    TRACE = "TRACE"


class Scope(StrEnum):
    """Supported provider lifetimes."""

    APPLICATION = "application"
    REQUEST = "request"


def _normalize_token(token: ServiceToken) -> ServiceToken:
    if isinstance(token, type):
        return token
    if isinstance(token, str) and token.strip():
        return token.strip()
    raise DefinitionError("service token must be a type or non-empty string")


def _normalize_path(path: str) -> str:
    if not isinstance(path, str):
        raise DefinitionError("route path must be a string")
    value = path.strip()
    if not value:
        raise DefinitionError("route path must not be empty")
    if any(character.isspace() for character in value) or "?" in value or "#" in value:
        raise DefinitionError(f"invalid route path: {path!r}")
    if "\x00" in value:
        raise DefinitionError("route path must not contain a null character")
    return "/" + value.lstrip("/")


def _normalize_methods(
    methods: tuple[HttpMethod, ...] | str | HttpMethod | Iterable[str | HttpMethod],
) -> tuple[HttpMethod, ...]:
    if isinstance(methods, (str, HttpMethod)):
        values = (methods,)
    else:
        values = normalize_iterable(methods, "route methods")
    if not values:
        raise DefinitionError("route must define at least one HTTP method")
    normalized: list[HttpMethod] = []
    for value in values:
        try:
            method = value if isinstance(value, HttpMethod) else HttpMethod(value.upper())
        except (AttributeError, TypeError, ValueError) as error:
            raise DefinitionError(f"unsupported HTTP method: {value!r}") from error
        if method not in normalized:
            normalized.append(method)
    return tuple(normalized)


def _normalize_tags(tags: Iterable[str]) -> tuple[str, ...]:
    if isinstance(tags, str):
        raise DefinitionError("route tags must be an iterable of strings")
    values = normalize_iterable(tags, "route tags")
    if not all(isinstance(tag, str) and tag.strip() for tag in values):
        raise DefinitionError("route tags must contain non-empty strings")
    return values


def _normalize_guards(guards: Iterable[GuardDefinition]) -> tuple[GuardDefinition, ...]:
    values = normalize_iterable(guards, "route guards")
    if not all(isinstance(item, GuardDefinition) for item in values):
        raise DefinitionError("route guards must contain GuardDefinition values")
    return values


def _normalize_interceptors(
    interceptors: Iterable[InterceptorDefinition],
) -> tuple[InterceptorDefinition, ...]:
    values = normalize_iterable(interceptors, "route interceptors")
    if not all(isinstance(item, InterceptorDefinition) for item in values):
        raise DefinitionError("route interceptors must contain InterceptorDefinition values")
    return values


def _normalize_tokens(tokens: Iterable[ServiceToken]) -> tuple[ServiceToken, ...]:
    return tuple(
        _normalize_token(token) for token in normalize_iterable(tokens, "provider dependencies")
    )


def _normalize_scope(scope: Scope | str) -> Scope:
    if isinstance(scope, Scope):
        return scope
    try:
        return Scope(scope)
    except (TypeError, ValueError) as error:
        raise DefinitionError(f"unsupported provider scope: {scope!r}") from error


def _normalize_hooks(hooks: Iterable[LifecycleHook], label: str) -> tuple[LifecycleHook, ...]:
    values = normalize_iterable(hooks, f"lifecycle {label} hooks")
    if not all(callable(hook) for hook in values):
        raise DefinitionError(f"lifecycle {label} hooks must be callable")
    return values


def _normalize_startup_hooks(hooks: Iterable[LifecycleHook]) -> tuple[LifecycleHook, ...]:
    return _normalize_hooks(hooks, "startup")


def _normalize_shutdown_hooks(hooks: Iterable[LifecycleHook]) -> tuple[LifecycleHook, ...]:
    return _normalize_hooks(hooks, "shutdown")


def _validate_status_code(_instance: object, _attribute: Any, value: int | None) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise DefinitionError("route status_code must be an integer")
    if not 100 <= value <= 599:
        raise DefinitionError("route status_code must be between 100 and 599")


def _normalize_model_values[ModelT](
    values: Iterable[ModelT],
    expected: type[ModelT],
    label: str,
) -> tuple[ModelT, ...]:
    normalized = normalize_iterable(values, f"application {label}")
    if not all(isinstance(value, expected) for value in normalized):
        raise DefinitionError(f"application {label} contain invalid values")
    return normalized


@define(frozen=True, slots=True)
class Inject:
    """Framework-independent marker for a provider-backed endpoint parameter."""

    token: ServiceToken = field(converter=_normalize_token)


def inject(token: ServiceToken) -> InjectedType:
    """Mark an endpoint parameter for Adapter-level dependency injection."""
    return cast("InjectedType", Inject(token))


@define(frozen=True, slots=True)
class RouteDefinition:
    """One explicit route and its framework-independent policies."""

    path: str = field(converter=_normalize_path)
    endpoint: Endpoint = field(validator=callable_validator("route endpoint"))
    methods: tuple[HttpMethod, ...] = field(
        default=(HttpMethod.GET,),
        converter=_normalize_methods,
    )
    name: str | None = field(
        default=None,
        validator=optional_non_empty_text_validator("route name"),
    )
    deprecated: bool = field(
        default=False,
        validator=bool_validator("route deprecated"),
    )
    include_in_schema: bool = field(
        default=True,
        validator=bool_validator("route include_in_schema"),
    )
    response_model: object | None = None
    status_code: int | None = field(default=None, validator=_validate_status_code)
    tags: tuple[str, ...] = field(default=(), converter=_normalize_tags)
    summary: str | None = field(
        default=None,
        validator=optional_non_empty_text_validator("route summary"),
    )
    description: str | None = field(
        default=None,
        validator=optional_non_empty_text_validator("route description"),
    )
    response_description: str | None = field(
        default=None,
        validator=optional_non_empty_text_validator("route response_description"),
    )
    operation_id: str | None = field(
        default=None,
        validator=optional_non_empty_text_validator("route operation_id"),
    )
    guards: tuple[GuardDefinition, ...] = field(default=(), converter=_normalize_guards)
    interceptors: tuple[InterceptorDefinition, ...] = field(
        default=(),
        converter=_normalize_interceptors,
    )

    def __attrs_post_init__(self) -> None:
        if self.operation_id is not None and len(self.methods) > 1:
            raise DefinitionError("route operation_id requires exactly one HTTP method")


@define(frozen=True, slots=True)
class ProviderDefinition:
    """One explicit provider and its dependency order."""

    token: ServiceToken = field(converter=_normalize_token)
    factory: ProviderFactory = field(validator=callable_validator("provider factory"))
    dependencies: tuple[ServiceToken, ...] = field(default=(), converter=_normalize_tokens)
    scope: Scope = field(default=Scope.REQUEST, converter=_normalize_scope)
    eager: bool = field(default=False, validator=bool_validator("provider eager"))
    disposer: Disposer | None = field(
        default=None,
        validator=optional_callable_validator("provider disposer"),
    )

    def __attrs_post_init__(self) -> None:
        if self.eager and self.scope is not Scope.APPLICATION:
            raise DefinitionError("only application providers can be eager")


@define(frozen=True, slots=True)
class LifecycleDefinition:
    """Application hooks that run outside request handling."""

    startup: tuple[LifecycleHook, ...] = field(default=(), converter=_normalize_startup_hooks)
    shutdown: tuple[LifecycleHook, ...] = field(default=(), converter=_normalize_shutdown_hooks)


def _normalize_routes(values: object) -> tuple[RouteDefinition, ...]:
    """Materialize route definitions and declaration-time route sources.

    ``ApplicationRouter`` intentionally lives in a separate module that depends
    on this module.  Detecting its framework-independent ``snapshot`` contract
    structurally keeps the dependency direction one-way while allowing
    ``ApplicationDefinition(routes=router)``.
    """
    if isinstance(values, RouteDefinition):
        return (values,)

    snapshot = getattr(values, "snapshot", None)
    if callable(snapshot):
        values = snapshot()

    normalized = normalize_iterable(cast("Iterable[object]", values), "routes")
    routes: list[RouteDefinition] = []
    for value in normalized:
        if isinstance(value, RouteDefinition):
            routes.append(value)
            continue

        nested_snapshot = getattr(value, "snapshot", None)
        if not callable(nested_snapshot):
            raise DefinitionError(
                "application routes must contain RouteDefinition or route sources",
            )
        routes.extend(_normalize_routes(nested_snapshot()))
    return tuple(routes)


def _normalize_providers(values: Iterable[ProviderDefinition]) -> tuple[ProviderDefinition, ...]:
    return _normalize_model_values(values, ProviderDefinition, "providers")


def _normalize_application_guards(
    values: Iterable[GuardDefinition],
) -> tuple[GuardDefinition, ...]:
    return _normalize_model_values(values, GuardDefinition, "guards")


def _normalize_application_interceptors(
    values: Iterable[InterceptorDefinition],
) -> tuple[InterceptorDefinition, ...]:
    return _normalize_model_values(values, InterceptorDefinition, "interceptors")


@define(frozen=True, slots=True)
class ApplicationDefinition:
    """Complete immutable description of one application."""

    routes: tuple[RouteDefinition, ...] = field(
        default=(),
        converter=_normalize_routes,
    )
    providers: tuple[ProviderDefinition, ...] = field(
        default=(),
        converter=_normalize_providers,
    )
    guards: tuple[GuardDefinition, ...] = field(
        default=(),
        converter=_normalize_application_guards,
    )
    interceptors: tuple[InterceptorDefinition, ...] = field(
        default=(),
        converter=_normalize_application_interceptors,
    )
    lifecycle: LifecycleDefinition = field(
        factory=LifecycleDefinition,
        validator=instance_validator(LifecycleDefinition, "application lifecycle"),
    )


def route(
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
) -> RouteDefinition:
    """Create one explicit route definition."""
    return RouteDefinition(
        path=path,
        endpoint=endpoint,
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


def provide(
    token: ServiceToken,
    factory: ProviderFactory | None = None,
    *,
    dependencies: Iterable[ServiceToken] = (),
    scope: Scope = Scope.REQUEST,
    eager: bool = False,
    disposer: Disposer | None = None,
) -> ProviderDefinition:
    """Create one explicit provider definition."""
    if factory is None:
        if not isinstance(token, type):
            raise DefinitionError("factory is required for string provider tokens")
        factory = token
    return ProviderDefinition(
        token=token,
        factory=factory,
        dependencies=dependencies,
        scope=scope,
        eager=eager,
        disposer=disposer,
    )


__all__ = [
    "ApplicationDefinition",
    "Disposer",
    "Endpoint",
    "HttpMethod",
    "Inject",
    "LifecycleDefinition",
    "ProviderDefinition",
    "ProviderFactory",
    "RouteDefinition",
    "Scope",
    "ServiceToken",
    "inject",
    "provide",
    "route",
]
