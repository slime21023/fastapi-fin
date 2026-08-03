"""FastAPI boundary for the 1.0.0 application model."""

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from functools import wraps
from inspect import Parameter, isawaitable, signature
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request

from ..application import (
    ApplicationDefinition,
    Inject,
    RouteDefinition,
    ServiceToken,
    assemble,
)
from ..application.model import ApplicationModel
from ..errors import AccessDeniedError, AdapterError, ResolutionError, RuntimeClosedError
from ..features.guards import enforce_guards
from ..features.interceptors import execute_interceptors
from ..runtime import ApplicationRuntime, RequestContext

Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[object]]


class FastAPIAdapter:
    """Translate an application definition into a FastAPI application."""

    @classmethod
    def create_app(
        cls,
        definition: ApplicationDefinition,
        *,
        title: str = "FastAPI-Fin application",
        version: str = "1.0.0",
        description: str = "",
        lifespan: Lifespan | None = None,
    ) -> FastAPI:
        """Create a FastAPI app with managed runtime and application lifecycle."""
        model = assemble(definition)
        runtime: ApplicationRuntime | None = None
        if lifespan is not None and not callable(lifespan):
            raise AdapterError("lifespan must be callable")

        def current_runtime() -> ApplicationRuntime:
            if runtime is None:
                raise RuntimeClosedError("application runtime is not active")
            return runtime

        @asynccontextmanager
        async def application_lifespan(app: FastAPI) -> AsyncIterator[None]:
            nonlocal runtime
            runtime = ApplicationRuntime(model)
            startup_completed = False
            try:
                await runtime.start()
                for hook in model.lifecycle.startup:
                    await _call_hook(hook)
                startup_completed = True
                if lifespan is None:
                    yield
                else:
                    async with lifespan(app):
                        yield
            finally:
                cleanup_errors: list[Exception] = []
                if startup_completed:
                    for hook in reversed(model.lifecycle.shutdown):
                        try:
                            await _call_hook(hook)
                        except Exception as error:
                            cleanup_errors.append(error)
                try:
                    if runtime is not None:
                        await runtime.stop()
                except Exception as error:
                    cleanup_errors.append(error)
                runtime = None
                if cleanup_errors:
                    raise ExceptionGroup("application shutdown failed", cleanup_errors)

        app = FastAPI(
            title=title,
            version=version,
            description=description,
            lifespan=application_lifespan,
        )
        app.include_router(cls._compile_router(model, current_runtime))
        return app

    @classmethod
    def mount(
        cls,
        app: FastAPI,
        definition: ApplicationDefinition,
    ) -> FastAPI:
        """Mount stateless routes into an existing FastAPI application.

        Applications with providers or lifecycle hooks must use ``create_app`` so
        that runtime ownership is explicit and startup/shutdown cannot be skipped.
        """
        if not isinstance(app, FastAPI):
            raise AdapterError("app must be a FastAPI instance")
        model = assemble(definition)
        if model.providers or model.lifecycle.startup or model.lifecycle.shutdown:
            raise AdapterError("managed definitions must be passed to create_app")
        app.include_router(cls._compile_router(model, None))
        return app

    @staticmethod
    def _compile_router(
        model: ApplicationModel,
        runtime_getter: Callable[[], ApplicationRuntime] | None,
    ) -> APIRouter:
        router = APIRouter()
        for route in model.routes:
            endpoint = _build_endpoint(model, route, runtime_getter)
            options: dict[str, Any] = {
                "methods": [method.value for method in route.methods],
                "deprecated": route.deprecated,
                "include_in_schema": route.include_in_schema,
            }
            if route.name is not None:
                options["name"] = route.name
            if route.response_model is not None:
                options["response_model"] = route.response_model
            if route.status_code is not None:
                options["status_code"] = route.status_code
            if route.tags:
                options["tags"] = list(route.tags)
            for name in (
                "summary",
                "description",
                "response_description",
                "operation_id",
            ):
                value = getattr(route, name)
                if value is not None:
                    options[name] = value
            router.add_api_route(route.path, endpoint, **options)
        return router


def _build_endpoint(
    model: ApplicationModel,
    route: RouteDefinition,
    runtime_getter: Callable[[], ApplicationRuntime] | None,
) -> Callable[..., object]:
    if _has_injected_parameter(route.endpoint) and runtime_getter is None:
        raise AdapterError("injected route parameters require create_app")
    endpoint = _adapt_injections(route.endpoint, runtime_getter)
    guards = (*model.guards, *route.guards)
    interceptors = (*model.interceptors, *route.interceptors)
    if not guards and not interceptors:
        return endpoint

    request_name: str | None = None
    final_signature = signature(endpoint)
    parameters = list(final_signature.parameters.values())
    if guards:
        request_name = _unique_parameter_name(parameters, "_fastapi_fin_request")
        request_parameter = Parameter(
            request_name,
            kind=Parameter.KEYWORD_ONLY,
            annotation=Request,
            default=_REQUEST_DEPENDENCY,
        )
        insertion_index = next(
            (
                index
                for index, parameter in enumerate(parameters)
                if parameter.kind is Parameter.VAR_KEYWORD
            ),
            len(parameters),
        )
        parameters.insert(insertion_index, request_parameter)
        final_signature = final_signature.replace(parameters=parameters)

    @wraps(endpoint)
    async def guarded_endpoint(*args: object, **kwargs: object) -> object:
        subject = kwargs.pop(request_name) if request_name is not None else None
        if guards:
            try:
                await enforce_guards(guards, subject)
            except AccessDeniedError as error:
                raise HTTPException(status_code=403, detail="forbidden") from error
        return await execute_interceptors(endpoint, args, kwargs, interceptors)

    endpoint_with_signature: Any = guarded_endpoint
    endpoint_with_signature.__signature__ = final_signature
    return endpoint_with_signature


def _adapt_injections(
    endpoint: Callable[..., object],
    runtime_getter: Callable[[], ApplicationRuntime] | None,
) -> Callable[..., object]:
    if runtime_getter is None:
        return endpoint
    original_signature = signature(endpoint)
    context_dependency = _make_context_dependency(runtime_getter)
    parameters = list(original_signature.parameters.values())
    changed = False
    for index, parameter in enumerate(parameters):
        marker = parameter.default
        if not isinstance(marker, Inject):
            continue
        parameters[index] = parameter.replace(
            default=Depends(
                _make_service_dependency(runtime_getter, context_dependency, marker.token)
            )
        )
        changed = True
    if not changed:
        return endpoint

    adapted_signature = original_signature.replace(parameters=parameters)

    @wraps(endpoint)
    async def adapted_endpoint(*args: object, **kwargs: object) -> object:
        result = endpoint(*args, **kwargs)
        if not isawaitable(result):
            return result
        return await result

    endpoint_with_signature: Any = adapted_endpoint
    endpoint_with_signature.__signature__ = adapted_signature
    return endpoint_with_signature


def _has_injected_parameter(endpoint: Callable[..., object]) -> bool:
    return any(
        isinstance(parameter.default, Inject)
        for parameter in signature(endpoint).parameters.values()
    )


def _make_service_dependency(
    runtime_getter: Callable[[], ApplicationRuntime],
    context_dependency: Callable[[], AsyncIterator[RequestContext]],
    token: ServiceToken,
) -> Callable[..., object]:
    context_marker = Depends(context_dependency)

    async def resolve_service(
        context: RequestContext = context_marker,
    ) -> object:
        try:
            return await runtime_getter().resolve(token, context)
        except ResolutionError as error:
            raise HTTPException(
                status_code=500,
                detail="dependency resolution failed",
            ) from error

    return resolve_service


def _make_context_dependency(
    runtime_getter: Callable[[], ApplicationRuntime],
) -> Callable[[], AsyncIterator[RequestContext]]:
    async def provide_context() -> AsyncIterator[RequestContext]:
        context = runtime_getter().new_request()
        try:
            yield context
        finally:
            await context.close()

    return provide_context


async def _request_identity(request: Request) -> Request:
    return request


_REQUEST_DEPENDENCY = Depends(_request_identity)


async def _call_hook(hook: Callable[[], object]) -> None:
    result = hook()
    if isawaitable(result):
        await result


def _unique_parameter_name(parameters: list[Parameter], base: str) -> str:
    names = {parameter.name for parameter in parameters}
    if base not in names:
        return base
    suffix = 2
    while f"{base}_{suffix}" in names:
        suffix += 1
    return f"{base}_{suffix}"


__all__ = ["FastAPIAdapter", "Lifespan"]
