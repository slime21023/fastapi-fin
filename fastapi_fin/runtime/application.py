"""Application and request runtime state."""

import asyncio
from collections.abc import Awaitable, Callable
from inspect import isawaitable

from attrs import define, field

from ..application import ProviderDefinition, Scope, ServiceToken
from ..application.model import ApplicationModel
from ..errors import ResolutionError, RuntimeClosedError


@define(slots=True)
class RequestContext:
    """Per-request provider values and explicit cleanup state."""

    values: dict[ServiceToken, object] = field(factory=dict)
    _owned: list[tuple[Callable[[object], object | Awaitable[object]], object]] = field(
        factory=list,
        repr=False,
    )
    _closed: bool = field(default=False, init=False, repr=False)

    @property
    def closed(self) -> bool:
        return self._closed

    def ensure_open(self) -> None:
        if self._closed:
            raise RuntimeClosedError("request context is closed")

    def track(
        self,
        value: object,
        disposer: Callable[[object], object | Awaitable[object]] | None,
    ) -> None:
        self.ensure_open()
        if disposer is not None:
            self._owned.append((disposer, value))

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        errors: list[Exception] = []
        for disposer, value in reversed(self._owned):
            try:
                result = disposer(value)
                if isawaitable(result):
                    await result
            except Exception as error:
                errors.append(error)
        self._owned.clear()
        self.values.clear()
        if errors:
            raise ExceptionGroup("request resource cleanup failed", errors)

    async def __aenter__(self) -> "RequestContext":
        self.ensure_open()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()


@define(slots=True, eq=False, repr=False)
class ApplicationRuntime:
    """Mutable execution state for one immutable application model."""

    model: ApplicationModel
    _application_values: dict[ServiceToken, object] = field(factory=dict, init=False, repr=False)
    _application_owned: list[tuple[Callable[[object], object | Awaitable[object]], object]] = field(
        factory=list, init=False, repr=False
    )
    _locks: dict[ServiceToken, asyncio.Lock] = field(factory=dict, init=False, repr=False)
    _started: bool = field(default=False, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    @property
    def started(self) -> bool:
        return self._started and not self._closed

    @property
    def closed(self) -> bool:
        return self._closed

    async def start(self) -> None:
        """Start the runtime and initialize eager application providers."""
        if self._closed:
            raise RuntimeClosedError("application runtime is closed")
        if self._started:
            return
        self._started = True
        try:
            for token in self.model.provider_order:
                provider = self.model.find_provider(token)
                if provider is not None and provider.eager:
                    await self.resolve(token)
        except Exception:
            await self.stop()
            raise

    async def stop(self) -> None:
        """Close application resources in reverse creation order."""
        if self._closed:
            return
        self._closed = True
        errors: list[Exception] = []
        for disposer, value in reversed(self._application_owned):
            try:
                result = disposer(value)
                if isawaitable(result):
                    await result
            except Exception as error:
                errors.append(error)
        self._application_owned.clear()
        self._application_values.clear()
        self._locks.clear()
        if errors:
            raise ExceptionGroup("application resource cleanup failed", errors)

    def new_request(self) -> RequestContext:
        if not self.started:
            raise RuntimeClosedError("application runtime is not started")
        return RequestContext()

    async def resolve(
        self,
        token: ServiceToken,
        context: RequestContext | None = None,
    ) -> object:
        """Resolve one provider using its declared dependency order."""
        if not self.started:
            raise RuntimeClosedError("application runtime is not started")
        provider = self.model.find_provider(token)
        if provider is None:
            raise ResolutionError(f"no provider found for token: {token!r}")
        if provider.scope is Scope.APPLICATION:
            return await self._resolve_application(provider)
        if context is None:
            raise ResolutionError(f"request context is required for token: {token!r}")
        context.ensure_open()
        if token in context.values:
            return context.values[token]
        value = await self._create(provider, context)
        context.values[token] = value
        context.track(value, provider.disposer)
        return value

    async def _resolve_application(self, provider: ProviderDefinition) -> object:
        if provider.token in self._application_values:
            return self._application_values[provider.token]
        lock = self._locks.setdefault(provider.token, asyncio.Lock())
        async with lock:
            if provider.token in self._application_values:
                return self._application_values[provider.token]
            value = await self._create(provider, None)
            self._application_values[provider.token] = value
            if provider.disposer is not None:
                self._application_owned.append((provider.disposer, value))
            return value

    async def _create(
        self,
        provider: ProviderDefinition,
        context: RequestContext | None,
    ) -> object:
        try:
            dependencies = [await self.resolve(token, context) for token in provider.dependencies]
            result = provider.factory(*dependencies)
            return await result if isawaitable(result) else result
        except (ResolutionError, RuntimeClosedError):
            raise
        except Exception as error:
            raise ResolutionError(
                f"provider factory failed for token: {provider.token!r}"
            ) from error


__all__ = ["ApplicationRuntime", "RequestContext"]
