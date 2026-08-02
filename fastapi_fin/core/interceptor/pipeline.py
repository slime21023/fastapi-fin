"""Composable endpoint interceptors independent from FastAPI."""

import asyncio
from collections.abc import Awaitable, Callable
from functools import wraps
from inspect import isawaitable, iscoroutine, iscoroutinefunction

from attrs import evolve, field, frozen, validators

from ..cache import CachePolicy, CacheStore
from ..errors import DeclarationError, RegistrationError
from ..types import (
    _normalize_optional_positive_number,
    _validate_integer,
    _validate_nonnegative_integer,
)

InterceptorNext = Callable[[], object]
InterceptorHandler = Callable[[InterceptorNext, tuple[object, ...], dict[str, object]], object]
ErrorHandler = Callable[[Exception], object | Awaitable[object]]
Endpoint = Callable[..., object]


def _normalize_name(name: str) -> str:
    if not isinstance(name, str):
        raise DeclarationError("interceptor name must be a string")
    normalized = name.strip()
    if not normalized:
        raise DeclarationError("interceptor name must not be empty")
    return normalized


def _validate_handler(_instance: object, _attribute: object, handler: InterceptorHandler) -> None:
    if not callable(handler):
        raise DeclarationError("interceptor handler must be callable")


def _validate_error_handler(
    _instance: object,
    _attribute: object,
    handler: ErrorHandler | None,
) -> None:
    if handler is not None and not callable(handler):
        raise DeclarationError("interceptor error_handler must be callable")


def _validate_interceptors(
    _instance: object,
    _attribute: object,
    interceptors: tuple["InterceptorSpec", ...],
) -> None:
    names: set[str] = set()
    for interceptor in interceptors:
        if not isinstance(interceptor, InterceptorSpec):
            raise DeclarationError("interceptor chain items must be InterceptorSpec instances")
        if interceptor.name in names:
            raise RegistrationError(f"interceptor is already registered: {interceptor.name!r}")
        names.add(interceptor.name)


def _normalize_interceptors(
    interceptors: tuple["InterceptorSpec", ...],
) -> tuple["InterceptorSpec", ...]:
    return tuple(sorted(interceptors, key=lambda interceptor: interceptor.order))


@frozen(slots=True, kw_only=True)
class InterceptorSpec:
    """Immutable interceptor configuration and callable."""

    name: str = field(converter=_normalize_name)
    handler: InterceptorHandler = field(validator=_validate_handler)
    order: int = field(default=0, validator=_validate_integer)
    retries: int = field(default=0, validator=_validate_nonnegative_integer)
    timeout: float | None = field(
        default=None,
        converter=_normalize_optional_positive_number,
    )
    error_handler: ErrorHandler | None = field(default=None, validator=_validate_error_handler)
    cache: CachePolicy | None = field(
        default=None,
        validator=validators.optional(validators.instance_of(CachePolicy)),
    )


@frozen(slots=True, kw_only=True)
class InterceptorChain:
    """Ordered immutable interceptor chain."""

    interceptors: tuple[InterceptorSpec, ...] = field(
        factory=tuple,
        converter=_normalize_interceptors,
        validator=_validate_interceptors,
    )

    def add(self, interceptor: InterceptorSpec) -> "InterceptorChain":
        """Return a new chain with an interceptor inserted by order."""
        if not isinstance(interceptor, InterceptorSpec):
            raise DeclarationError("interceptor must be an InterceptorSpec instance")
        if any(item.name == interceptor.name for item in self.interceptors):
            raise RegistrationError(f"interceptor is already registered: {interceptor.name!r}")
        ordered = tuple(sorted((*self.interceptors, interceptor), key=lambda item: item.order))
        return evolve(self, interceptors=ordered)

    def apply(self, endpoint: Endpoint) -> Endpoint:
        """Wrap an endpoint while preserving its signature metadata."""
        async_pipeline = iscoroutinefunction(endpoint) or any(
            iscoroutinefunction(item.handler) or iscoroutinefunction(item.error_handler)
            for item in self.interceptors
        )
        if not async_pipeline and any(item.timeout is not None for item in self.interceptors):
            raise DeclarationError(
                "interceptor timeout requires an async endpoint or interceptor handler"
            )
        if async_pipeline:
            return self._apply_async(endpoint)
        return self._apply_sync(endpoint)

    def _apply_sync(self, endpoint: Endpoint) -> Endpoint:
        cache_store = CacheStore()

        @wraps(endpoint)
        def wrapped(*args: object, **kwargs: object) -> object:
            def invoke(index: int) -> object:
                if index == len(self.interceptors):
                    return endpoint(*args, **kwargs)
                interceptor = self.interceptors[index]
                return self._run_sync(
                    interceptor,
                    lambda: interceptor.handler(
                        lambda: invoke(index + 1),
                        args,
                        kwargs,
                    ),
                    cache_store=cache_store,
                    args=args,
                    kwargs=kwargs,
                )

            return invoke(0)

        return wrapped

    def _apply_async(self, endpoint: Endpoint) -> Endpoint:
        cache_store = CacheStore()

        @wraps(endpoint)
        async def wrapped(*args: object, **kwargs: object) -> object:
            async def invoke(index: int) -> object:
                if index == len(self.interceptors):
                    result = endpoint(*args, **kwargs)
                else:
                    interceptor = self.interceptors[index]
                    result = await self._run_async(
                        interceptor,
                        lambda: interceptor.handler(
                            lambda: invoke(index + 1),
                            args,
                            kwargs,
                        ),
                        cache_store=cache_store,
                        args=args,
                        kwargs=kwargs,
                    )
                return await result if isawaitable(result) else result

            return await invoke(0)

        return wrapped

    @staticmethod
    def _run_sync(
        interceptor: InterceptorSpec,
        call: Callable[[], object],
        *,
        cache_store: CacheStore,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> object:
        cached = _lookup_cache(interceptor, cache_store, args, kwargs)
        if cached[0]:
            return cached[1]
        for attempt in range(interceptor.retries + 1):
            try:
                result = call()
            except Exception as error:
                if attempt == interceptor.retries:
                    if interceptor.error_handler is not None:
                        result = interceptor.error_handler(error)
                        result = _require_sync_result(result)
                        _store_cache(interceptor, cache_store, args, kwargs, result)
                        return result
                    raise
            else:
                result = _require_sync_result(result)
                _store_cache(interceptor, cache_store, args, kwargs, result)
                return result
        raise RuntimeError("interceptor retry loop ended unexpectedly")

    @staticmethod
    async def _run_async(
        interceptor: InterceptorSpec,
        call: Callable[[], object],
        *,
        cache_store: CacheStore,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> object:
        cached = _lookup_cache(interceptor, cache_store, args, kwargs)
        if cached[0]:
            return cached[1]
        for attempt in range(interceptor.retries + 1):
            try:
                result = call()
                awaitable = result if isawaitable(result) else _completed(result)
                if interceptor.timeout is None:
                    result = await awaitable
                else:
                    result = await asyncio.wait_for(awaitable, timeout=interceptor.timeout)
                _store_cache(interceptor, cache_store, args, kwargs, result)
                return result
            except Exception as error:
                if attempt == interceptor.retries:
                    if interceptor.error_handler is not None:
                        translated = interceptor.error_handler(error)
                        result = await translated if isawaitable(translated) else translated
                        _store_cache(interceptor, cache_store, args, kwargs, result)
                        return result
                    raise
        raise RuntimeError("interceptor retry loop ended unexpectedly")


async def _completed(value: object) -> object:
    return value


def _lookup_cache(
    interceptor: InterceptorSpec,
    cache_store: CacheStore,
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> tuple[bool, object]:
    if interceptor.cache is None:
        return False, None
    return cache_store.lookup(interceptor.name, interceptor.cache, args, kwargs)


def _store_cache(
    interceptor: InterceptorSpec,
    cache_store: CacheStore,
    args: tuple[object, ...],
    kwargs: dict[str, object],
    value: object,
) -> None:
    if interceptor.cache is not None:
        cache_store.store(interceptor.name, interceptor.cache, args, kwargs, value)


def _require_sync_result(value: object) -> object:
    if not isawaitable(value):
        return value
    if iscoroutine(value):
        value.close()
    raise TypeError("async interceptor result requires an async pipeline")
