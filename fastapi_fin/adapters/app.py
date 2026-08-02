"""FastAPI application adapter orchestration."""

from collections.abc import Callable, Iterable

from fastapi import APIRouter, FastAPI

from ..application.compiler import CompiledRoute
from ..application.registry import MetadataRegistry
from ..core.dependency import ContainerRuntime, ServiceToken
from ..core.events import EventDispatcher
from ..core.guard import GuardPolicy, GuardRule
from ..core.interceptor import InterceptorChain, InterceptorSpec
from .dependencies import container_dependency
from .errors import AdapterError
from .lifespan import LifespanHandler, compose_lifespan
from .router import ControllerFactory, compile_router

__all__ = ["CompiledRoute", "FastAPIAdapter", "LifespanHandler", "container_dependency"]


def _normalize_iterable[T](values: Iterable[T], label: str) -> tuple[T, ...]:
    try:
        return tuple(values)
    except TypeError as error:
        raise AdapterError(f"{label} must be iterable") from error


class FastAPIAdapter:
    """Attach FastAPI-Fin routes to an existing FastAPI application."""

    def __init__(
        self,
        app: FastAPI,
        *,
        controller_factory: ControllerFactory | None = None,
        container_runtime: ContainerRuntime | None = None,
        guard_subject_provider: Callable[..., object] | None = None,
        global_guards: Iterable[GuardRule] = (),
        global_interceptors: Iterable[InterceptorSpec] = (),
        event_dispatcher: EventDispatcher | None = None,
    ) -> None:
        if not isinstance(app, FastAPI):
            raise AdapterError("app must be a FastAPI instance")
        if controller_factory is not None and not callable(controller_factory):
            raise AdapterError("controller_factory must be callable")
        if container_runtime is not None and not isinstance(container_runtime, ContainerRuntime):
            raise AdapterError("container_runtime must be a ContainerRuntime instance")
        if guard_subject_provider is not None and not callable(guard_subject_provider):
            raise AdapterError("guard_subject_provider must be callable")
        if event_dispatcher is not None and not isinstance(event_dispatcher, EventDispatcher):
            raise AdapterError("event_dispatcher must be an EventDispatcher instance")
        self._app = app
        self._controller_factory = controller_factory
        self._container_runtime = container_runtime
        self._guard_subject_provider = guard_subject_provider
        self._global_guards = GuardPolicy(
            rules=_normalize_iterable(global_guards, "global guards")
        ).rules
        self._global_interceptors = InterceptorChain(
            interceptors=_normalize_iterable(global_interceptors, "global interceptors")
        ).interceptors
        self._event_dispatcher = event_dispatcher

    def compile_router(self, registry: MetadataRegistry) -> APIRouter:
        """Create a new ``APIRouter`` from an immutable registry snapshot."""

        if not isinstance(registry, MetadataRegistry):
            raise AdapterError("registry must be a MetadataRegistry instance")

        return compile_router(
            registry,
            controller_factory=self._controller_factory,
            container_runtime=self._container_runtime,
            guard_subject_provider=self._guard_subject_provider,
            global_guards=self._global_guards,
            global_interceptors=self._global_interceptors,
        )

    def include(self, registry: MetadataRegistry) -> FastAPI:
        """Include routes in the existing app without changing its lifespan."""

        if self._container_runtime is not None or self._event_dispatcher is not None:
            raise AdapterError(
                "include() cannot install runtime lifecycle; use FastAPIAdapter.create_app()"
            )
        self._app.include_router(self.compile_router(registry))
        return self._app

    @classmethod
    def create_app(
        cls,
        registry: MetadataRegistry,
        *,
        lifespan: LifespanHandler | None = None,
        controller_factory: ControllerFactory | None = None,
        container_runtime: ContainerRuntime | None = None,
        guard_subject_provider: Callable[..., object] | None = None,
        global_guards: Iterable[GuardRule] = (),
        global_interceptors: Iterable[InterceptorSpec] = (),
        event_dispatcher: EventDispatcher | None = None,
    ) -> FastAPI:
        """Create a FastAPI app when runtime lifecycle integration is required."""

        if not isinstance(registry, MetadataRegistry):
            raise AdapterError("registry must be a MetadataRegistry instance")
        if lifespan is not None and not callable(lifespan):
            raise AdapterError("lifespan must be callable")
        effective_lifespan = compose_lifespan(
            lifespan,
            runtime=container_runtime,
            dispatcher=event_dispatcher,
        )
        app = FastAPI() if effective_lifespan is None else FastAPI(lifespan=effective_lifespan)
        adapter = cls(
            app,
            controller_factory=controller_factory,
            container_runtime=container_runtime,
            guard_subject_provider=guard_subject_provider,
            global_guards=global_guards,
            global_interceptors=global_interceptors,
            event_dispatcher=event_dispatcher,
        )
        app.include_router(adapter.compile_router(registry))
        return app

    def dependency(self, token: ServiceToken) -> Callable[..., object]:
        """Create a FastAPI dependency backed by the container runtime."""

        if self._container_runtime is None:
            raise AdapterError("container_runtime is required for service dependencies")
        return container_dependency(self._container_runtime, token)
