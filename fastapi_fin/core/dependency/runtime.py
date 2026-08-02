"""Runtime resolution and resource lifecycle for registered providers."""

import ast
import asyncio
from concurrent.futures import Future
from inspect import Parameter, Signature, isawaitable, iscoroutine, isfunction, ismethod, signature
import sys
from threading import RLock
import typing
from typing import Annotated, ForwardRef, Self, get_args, get_origin, get_type_hints

from attrs import define, field, setters

from ..errors import ResolutionError, RuntimeClosedError
from ..types import Scope
from .providers import Provider, ProviderRegistry, ServiceFactory, ServiceToken, _normalize_token


@define(slots=True, kw_only=True)
class ResolutionContext:
    """Request-scoped values and cycle detection state."""

    values: dict[ServiceToken, object] = field(factory=dict)
    resolving: list[ServiceToken] = field(factory=list)
    _owned_values: list[object] = field(factory=list, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    @property
    def closed(self) -> bool:
        """Whether this context has already released its owned resources."""
        return self._closed

    def __enter__(self) -> Self:
        """Enter a synchronous context that owns request/transient resources."""
        if self._closed:
            raise ResolutionError("resolution context is already closed")
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: object,
    ) -> None:
        """Close owned resources when leaving a synchronous context."""
        self.close()

    async def __aenter__(self) -> Self:
        """Enter an asynchronous context that owns request/transient resources."""
        if self._closed:
            raise ResolutionError("resolution context is already closed")
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: object,
    ) -> None:
        """Close owned resources when leaving an asynchronous context."""
        await self.close_async()

    def track(self, value: object) -> None:
        """Track one request/transient value for eventual resource cleanup."""
        if self._closed:
            raise ResolutionError("resolution context is already closed")
        if _has_disposer(value) and not any(item is value for item in self._owned_values):
            self._owned_values.append(value)

    def close(self) -> None:
        """Release owned resources synchronously in reverse creation order."""
        if self._closed:
            return
        values = tuple(self._owned_values)
        _ensure_sync_cleanup(values, "resolution context")
        self._closed = True
        self._owned_values.clear()
        self.values.clear()
        self.resolving.clear()
        _dispose_sync_values(values, "resolution context")

    async def close_async(self) -> None:
        """Release owned resources asynchronously in reverse creation order."""
        if self._closed:
            return
        self._closed = True
        values = tuple(self._owned_values)
        self._owned_values.clear()
        self.values.clear()
        self.resolving.clear()
        await _dispose_async_values(values, "resolution context")


@define(slots=True, kw_only=True)
class ContainerRuntime:
    """Runtime cache for an immutable provider registry."""

    providers: ProviderRegistry = field(on_setattr=setters.frozen)
    singleton_values: dict[ServiceToken, object] = field(factory=dict)
    # A concurrent Future is shared by sync threads and async event loops.
    # asyncio.Lock cannot coordinate those two execution domains.
    _singleton_states: dict[ServiceToken, Future[object]] = field(
        factory=dict,
        init=False,
        repr=False,
    )
    _singleton_state_lock: RLock = field(factory=RLock, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    @property
    def closed(self) -> bool:
        """Whether this runtime has released its application resources."""
        return self._closed

    def initialize(self) -> None:
        """Eagerly initialize all non-lazy providers synchronously."""
        for provider in self.providers.providers:
            if not provider.lazy:
                if provider.scope is not Scope.SINGLETON:
                    raise ResolutionError("only singleton providers can be eagerly initialized")
                self.resolve(provider.token)

    async def initialize_async(self) -> None:
        """Eagerly initialize all non-lazy providers, including async factories."""
        for provider in self.providers.providers:
            if not provider.lazy:
                if provider.scope is not Scope.SINGLETON:
                    raise ResolutionError("only singleton providers can be eagerly initialized")
                await self.resolve_async(provider.token)

    def close(self) -> None:
        """Release singleton resources synchronously in reverse creation order."""
        if self._closed:
            return
        values = tuple(self.singleton_values.values())
        _ensure_sync_cleanup(values, "container runtime")
        with self._singleton_state_lock:
            if self._closed:
                return
            self._closed = True
            self.singleton_values.clear()
            pending = tuple(self._singleton_states.values())
            self._singleton_states.clear()
        self._fail_pending_singletons(pending)
        _dispose_sync_values(values, "container runtime")

    async def close_async(self) -> None:
        """Release singleton resources asynchronously in reverse creation order."""
        if self._closed:
            return
        values = tuple(self.singleton_values.values())
        with self._singleton_state_lock:
            if self._closed:
                return
            self._closed = True
            self.singleton_values.clear()
            pending = tuple(self._singleton_states.values())
            self._singleton_states.clear()
        self._fail_pending_singletons(pending)
        await _dispose_async_values(values, "container runtime")

    def resolve(
        self,
        token: ServiceToken,
        context: ResolutionContext | None = None,
    ) -> object:
        """Resolve a provider using singleton, request, or transient semantics."""
        self._ensure_open()
        normalized_token = _normalize_token(token)
        provider = self.providers.find(normalized_token)
        if provider is None:
            raise ResolutionError(f"no provider found for token: {normalized_token!r}")

        request_context = context or ResolutionContext()
        if request_context.closed:
            raise ResolutionError("resolution context is already closed")
        if provider.scope is Scope.SINGLETON and normalized_token in self.singleton_values:
            return self.singleton_values[normalized_token]
        if provider.scope is Scope.REQUEST and normalized_token in request_context.values:
            return request_context.values[normalized_token]
        if provider.scope is Scope.SINGLETON:
            if normalized_token in request_context.resolving:
                raise _circular_dependency_error(normalized_token, request_context)
            cached, state, owner = self._claim_singleton(normalized_token)
            if state is None:
                return cached
            if not owner:
                return self._wait_for_singleton_sync(state)
            try:
                value = self._resolve_sync_uncached(
                    provider,
                    normalized_token,
                    request_context,
                )
            except BaseException as error:
                self._fail_singleton(normalized_token, state, error)
                raise
            self._publish_singleton(normalized_token, state, value)
            return value
        return self._resolve_sync_uncached(provider, normalized_token, request_context)

    def _resolve_sync_uncached(
        self,
        provider: Provider,
        normalized_token: ServiceToken,
        request_context: ResolutionContext,
    ) -> object:
        if normalized_token in request_context.resolving:
            raise _circular_dependency_error(normalized_token, request_context)
        self._validate_scope_dependency(provider, request_context)

        request_context.resolving.append(normalized_token)
        try:
            value = self._call_factory(provider.factory, request_context)
        finally:
            request_context.resolving.pop()

        if provider.scope is not Scope.SINGLETON:
            request_context.track(value)
            if provider.scope is Scope.REQUEST:
                request_context.values[normalized_token] = value
        return value

    def _call_factory(
        self,
        factory: ServiceFactory,
        context: ResolutionContext,
    ) -> object:
        parameters, annotations = _factory_parameters(factory)
        dependencies = {
            parameter.name: self.resolve(_parameter_token(parameter, annotations), context)
            for parameter in parameters
            if _requires_dependency(parameter, annotations)
        }

        try:
            value = factory(**dependencies)
            if isawaitable(value):
                if iscoroutine(value):
                    value.close()
                raise ResolutionError(f"async service factory requires resolve_async: {factory!r}")
            return value
        except TypeError as error:
            raise ResolutionError(f"failed to call service factory: {factory!r}") from error

    async def resolve_async(
        self,
        token: ServiceToken,
        context: ResolutionContext | None = None,
    ) -> object:
        """Resolve sync or async factories using the same lifecycle rules."""
        self._ensure_open()
        normalized_token = _normalize_token(token)
        provider = self.providers.find(normalized_token)
        if provider is None:
            raise ResolutionError(f"no provider found for token: {normalized_token!r}")

        request_context = context or ResolutionContext()
        if request_context.closed:
            raise ResolutionError("resolution context is already closed")

        if provider.scope is Scope.SINGLETON:
            if normalized_token in request_context.resolving:
                raise _circular_dependency_error(normalized_token, request_context)
            cached, state, owner = self._claim_singleton(normalized_token)
            if state is None:
                return cached
            if not owner:
                return await asyncio.wrap_future(state)
            try:
                value = await self._resolve_async_uncached(
                    provider,
                    normalized_token,
                    request_context,
                )
            except BaseException as error:
                self._fail_singleton(normalized_token, state, error)
                raise
            self._publish_singleton(normalized_token, state, value)
            return value

        return await self._resolve_async_uncached(provider, normalized_token, request_context)

    async def _resolve_async_uncached(
        self,
        provider: Provider,
        normalized_token: ServiceToken,
        request_context: ResolutionContext,
    ) -> object:
        if provider.scope is Scope.REQUEST and normalized_token in request_context.values:
            return request_context.values[normalized_token]
        if normalized_token in request_context.resolving:
            raise _circular_dependency_error(normalized_token, request_context)
        self._validate_scope_dependency(provider, request_context)

        request_context.resolving.append(normalized_token)
        try:
            value = await self._call_factory_async(provider.factory, request_context)
        finally:
            request_context.resolving.pop()

        if provider.scope is not Scope.SINGLETON:
            request_context.track(value)
            if provider.scope is Scope.REQUEST:
                request_context.values[normalized_token] = value
        return value

    async def _call_factory_async(
        self,
        factory: ServiceFactory,
        context: ResolutionContext,
    ) -> object:
        parameters, annotations = _factory_parameters(factory)
        dependencies = {
            parameter.name: await self.resolve_async(
                _parameter_token(parameter, annotations), context
            )
            for parameter in parameters
            if _requires_dependency(parameter, annotations)
        }

        try:
            value = factory(**dependencies)
            return await value if isawaitable(value) else value
        except TypeError as error:
            raise ResolutionError(f"failed to call service factory: {factory!r}") from error

    def _validate_scope_dependency(
        self,
        provider: Provider,
        context: ResolutionContext,
    ) -> None:
        if provider.scope is not Scope.REQUEST:
            return
        for parent_token in context.resolving:
            parent_provider = self.providers.find(parent_token)
            if parent_provider is not None and parent_provider.scope is Scope.SINGLETON:
                raise ResolutionError(
                    "singleton services cannot depend on request-scoped services: "
                    f"{parent_token!r} -> {provider.token!r}"
                )

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeClosedError("container runtime is already closed")

    def _claim_singleton(
        self,
        token: ServiceToken,
    ) -> tuple[object, Future[object] | None, bool]:
        with self._singleton_state_lock:
            self._ensure_open()
            if token in self.singleton_values:
                return self.singleton_values[token], None, False
            state = self._singleton_states.get(token)
            if state is not None:
                return None, state, False
            state = Future()
            self._singleton_states[token] = state
            return None, state, True

    def _publish_singleton(
        self,
        token: ServiceToken,
        state: Future[object],
        value: object,
    ) -> None:
        with self._singleton_state_lock:
            if self._closed:
                error = RuntimeClosedError("container runtime is already closed")
                self._fail_singleton_locked(token, state, error)
                raise error
            self.singleton_values[token] = value
            self._singleton_states.pop(token, None)
            state.set_result(value)

    def _fail_singleton(
        self,
        token: ServiceToken,
        state: Future[object],
        error: BaseException,
    ) -> None:
        with self._singleton_state_lock:
            self._fail_singleton_locked(token, state, error)

    def _fail_singleton_locked(
        self,
        token: ServiceToken,
        state: Future[object],
        error: BaseException,
    ) -> None:
        self._singleton_states.pop(token, None)
        if not state.done():
            state.set_exception(error)
            state.exception()

    def _fail_pending_singletons(self, states: tuple[Future[object], ...]) -> None:
        error = RuntimeClosedError("container runtime is already closed")
        for state in states:
            if not state.done():
                state.set_exception(error)
                state.exception()

    @staticmethod
    def _wait_for_singleton_sync(state: Future[object]) -> object:
        if not state.done():
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                pass
            else:
                raise ResolutionError(
                    "synchronous resolution cannot wait for an async singleton "
                    "inside a running event loop"
                )
        return state.result()


def _factory_parameters(
    factory: ServiceFactory,
) -> tuple[tuple[Parameter, ...], dict[str, object]]:
    try:
        parameters = tuple(signature(factory).parameters.values())
    except (TypeError, ValueError) as error:
        raise ResolutionError(f"cannot inspect service factory: {factory!r}") from error

    annotation_source: object = factory
    if isinstance(factory, type):
        annotation_source = factory.__init__
    elif not (isfunction(factory) or ismethod(factory)):
        annotation_source = factory.__call__

    try:
        annotations = get_type_hints(annotation_source, include_extras=True)
    except (NameError, TypeError) as error:
        raw_annotations = getattr(annotation_source, "__annotations__", None)
        if not isinstance(raw_annotations, dict):
            raise ResolutionError(
                f"cannot resolve service factory annotations: {factory!r}"
            ) from error
        annotations = {
            name: _normalize_raw_annotation(annotation, annotation_source)
            for name, annotation in raw_annotations.items()
        }
    return parameters, annotations


def _requires_dependency(parameter: Parameter, annotations: dict[str, object]) -> bool:
    if parameter.kind in (Parameter.VAR_POSITIONAL, Parameter.VAR_KEYWORD):
        return False
    if parameter.kind is Parameter.POSITIONAL_ONLY:
        raise ResolutionError(
            f"positional-only service dependencies are unsupported: {parameter.name!r}"
        )
    if parameter.name not in annotations and parameter.annotation is Signature.empty:
        if parameter.default is not Signature.empty:
            return False
        raise ResolutionError(
            f"service factory parameter lacks a token annotation: {parameter.name!r}"
        )
    return True


def _parameter_token(parameter: Parameter, annotations: dict[str, object]) -> ServiceToken:
    token = _unwrap_annotated(annotations.get(parameter.name, parameter.annotation))
    if not isinstance(token, (str, type)):
        raise ResolutionError(f"service dependency annotation is not a token: {parameter.name!r}")
    return token


def _unwrap_annotated(annotation: object) -> object:
    while get_origin(annotation) is Annotated:
        arguments = get_args(annotation)
        if not arguments:
            break
        annotation = arguments[0]
    if isinstance(annotation, ForwardRef):
        return annotation.__forward_arg__
    return annotation


def _normalize_raw_annotation(annotation: object, annotation_source: object) -> object:
    if isinstance(annotation, str):
        normalized = annotation.strip()
        if len(normalized) >= 2 and normalized[0] == normalized[-1] == '"':
            return normalized[1:-1]
        if len(normalized) >= 2 and normalized[0] == normalized[-1] == "'":
            return normalized[1:-1]
        if _is_annotated_expression(normalized):
            return _extract_annotated_token(normalized, annotation_source)
        return normalized
    return annotation


def _is_annotated_expression(annotation: str) -> bool:
    try:
        expression = ast.parse(annotation, mode="eval").body
    except SyntaxError:
        return False
    if not isinstance(expression, ast.Subscript):
        return False
    return (isinstance(expression.value, ast.Name) and expression.value.id == "Annotated") or (
        isinstance(expression.value, ast.Attribute) and expression.value.attr == "Annotated"
    )


def _extract_annotated_token(annotation: str, annotation_source: object) -> object:
    try:
        expression = ast.parse(annotation, mode="eval").body
    except SyntaxError:
        return annotation
    if not isinstance(expression, ast.Subscript):
        return annotation

    arguments = (
        expression.slice.elts if isinstance(expression.slice, ast.Tuple) else (expression.slice,)
    )
    if not arguments:
        return annotation
    first_argument = arguments[0]
    if isinstance(first_argument, ast.Constant) and isinstance(first_argument.value, str):
        return first_argument.value
    if isinstance(first_argument, ast.Name):
        candidate = _annotation_namespace(annotation_source).get(first_argument.id)
        if isinstance(candidate, (str, type)):
            return candidate
    return annotation


def _annotation_namespace(annotation_source: object) -> dict[str, object]:
    namespace = dict(getattr(annotation_source, "__globals__", {}))
    module_name = getattr(annotation_source, "__module__", None)
    module = sys.modules.get(module_name) if isinstance(module_name, str) else None
    if module is not None:
        namespace.update(vars(module))
    namespace.update(vars(typing))
    namespace["Annotated"] = Annotated
    return namespace


def _circular_dependency_error(
    token: ServiceToken,
    context: ResolutionContext,
) -> ResolutionError:
    cycle = " -> ".join(map(str, (*context.resolving, token)))
    return ResolutionError(f"circular dependency detected: {cycle}")


def _has_disposer(value: object) -> bool:
    return any(
        callable(getattr(value, name, None))
        for name in ("aclose", "__aexit__", "close", "__exit__")
    )


def _ensure_sync_cleanup(values: tuple[object, ...], scope: str) -> None:
    if any(
        callable(getattr(value, name, None)) for value in values for name in ("aclose", "__aexit__")
    ):
        raise ResolutionError(f"async resource cleanup requires close_async: {scope}")


def _dispose_sync(value: object) -> None:
    if callable(getattr(value, "aclose", None)) or callable(getattr(value, "__aexit__", None)):
        raise ResolutionError("async resource cleanup requires close_async")

    for name in ("close", "__exit__"):
        disposer = getattr(value, name, None)
        if not callable(disposer):
            continue
        result = disposer() if name == "close" else disposer(None, None, None)
        if isawaitable(result):
            if iscoroutine(result):
                result.close()
            raise ResolutionError("async resource cleanup requires close_async")
        return


async def _dispose_async(value: object) -> None:
    for name in ("aclose", "__aexit__", "close", "__exit__"):
        disposer = getattr(value, name, None)
        if not callable(disposer):
            continue
        result = disposer() if name in {"aclose", "close"} else disposer(None, None, None)
        if isawaitable(result):
            await result
        return


def _dispose_sync_values(values: tuple[object, ...], scope: str) -> None:
    errors: list[Exception] = []
    disposed: set[int] = set()
    for value in reversed(values):
        if id(value) in disposed or not _has_disposer(value):
            continue
        disposed.add(id(value))
        try:
            _dispose_sync(value)
        except Exception as error:
            errors.append(error)
    _raise_cleanup_errors(errors, scope)


async def _dispose_async_values(values: tuple[object, ...], scope: str) -> None:
    errors: list[Exception] = []
    disposed: set[int] = set()
    for value in reversed(values):
        if id(value) in disposed or not _has_disposer(value):
            continue
        disposed.add(id(value))
        try:
            await _dispose_async(value)
        except Exception as error:
            errors.append(error)
    _raise_cleanup_errors(errors, scope)


def _raise_cleanup_errors(errors: list[Exception], scope: str) -> None:
    if not errors:
        return
    if len(errors) == 1:
        raise errors[0]
    raise ExceptionGroup(f"multiple errors while closing {scope}", errors)
