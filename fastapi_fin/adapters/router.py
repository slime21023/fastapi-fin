"""Translate compiled routes into FastAPI's public router API."""

from collections.abc import Callable
from enum import Enum
from typing import Any, TypedDict, cast

from fastapi import APIRouter, Depends, HTTPException

from ..application.compiler import compile_application
from ..application.registry import ApplicationRegistry
from ..core.dependency import ContainerRuntime
from ..core.guard import GuardPolicy, GuardRule
from ..core.interceptor import InterceptorChain, InterceptorSpec
from ..core.metadata import ControllerMetadata, Endpoint, RouteMetadata
from .dependencies import (
    _invoke_current_controller_async,
    build_request_controller_endpoint,
)
from .errors import AdapterError

ControllerFactory = Callable[[type[object]], object]

__all__ = ["ControllerFactory", "compile_router"]


class _FastAPIRouteOptions(TypedDict, total=False):
    response_model: Any
    status_code: int
    tags: list[str | Enum]
    summary: str
    description: str
    response_description: str
    operation_id: str


def compile_router(
    registry: ApplicationRegistry,
    *,
    controller_factory: ControllerFactory | None,
    runtime: ContainerRuntime | None,
    guard_subject_provider: Callable[..., object] | None,
    global_guards: tuple[GuardRule, ...],
    global_interceptors: tuple[InterceptorSpec, ...],
) -> APIRouter:
    """Compile the current registry snapshot into a new ``APIRouter``."""

    router = APIRouter()
    instances = {
        id(controller_metadata): _create_controller(
            controller_metadata,
            controller_factory=controller_factory,
            runtime=runtime,
        )
        for controller_metadata in registry.metadata.controllers
    }

    compiled_application = compile_application(
        registry,
        endpoint_resolver=lambda controller_metadata, route: _compile_route(
            controller_metadata,
            instances[id(controller_metadata)],
            route,
            runtime=runtime,
        ),
        global_guards=global_guards,
        global_interceptors=global_interceptors,
    )
    for compiled in compiled_application.routes:
        metadata = compiled.metadata
        router.add_api_route(
            metadata.path,
            compiled.endpoint,
            methods=[method.value for method in metadata.methods],
            name=metadata.name,
            deprecated=metadata.deprecated,
            include_in_schema=not metadata.internal,
            dependencies=_route_dependencies(metadata, guard_subject_provider),
            **_fastapi_route_options(metadata),
        )
    return router


def _create_controller(
    metadata: ControllerMetadata,
    *,
    controller_factory: ControllerFactory | None,
    runtime: ContainerRuntime | None,
) -> object | None:
    if (
        controller_factory is None
        and runtime is not None
        and runtime.providers.find(metadata.controller) is not None
    ):
        return None

    factory = controller_factory or _default_controller_factory
    try:
        return factory(metadata.controller)
    except TypeError as error:
        raise AdapterError(f"controller {metadata.name!r} requires a supported factory") from error


def _compile_route(
    controller_metadata: ControllerMetadata,
    instance: object | None,
    metadata: RouteMetadata,
    *,
    runtime: ContainerRuntime | None,
) -> Endpoint:
    endpoint_name = getattr(metadata.endpoint, "__name__", metadata.name)
    if instance is None:
        if runtime is None:
            raise AdapterError("container runtime is required for lazy controller resolution")
        endpoint_invoker = None
        if metadata.interceptors:

            async def invoke_controller(*args: object, **kwargs: object) -> object:
                return await _invoke_current_controller_async(
                    endpoint_name,
                    *args,
                    **kwargs,
                )

            endpoint_invoker = InterceptorChain(interceptors=metadata.interceptors).apply(
                invoke_controller
            )
        endpoint = build_request_controller_endpoint(
            runtime,
            controller_metadata,
            metadata.endpoint,
            endpoint_name,
            endpoint_invoker=endpoint_invoker,
        )
    else:
        endpoint = getattr(instance, endpoint_name, None)
        if endpoint is None:
            raise AdapterError(
                f"controller {metadata.name!r} does not expose endpoint {endpoint_name!r}"
            )
    compiled_endpoint = cast("Endpoint", endpoint)
    if metadata.interceptors and instance is not None:
        compiled_endpoint = InterceptorChain(interceptors=metadata.interceptors).apply(
            compiled_endpoint
        )
    return compiled_endpoint


def _route_dependencies(
    metadata: RouteMetadata,
    subject_provider: Callable[..., object] | None,
) -> list[Any] | None:
    if not metadata.guards:
        return None
    policy = GuardPolicy(rules=metadata.guards)
    if subject_provider is None:

        async def check() -> None:
            await _enforce_policy(policy, None)

    else:

        async def check(subject: object = Depends(subject_provider)) -> None:
            await _enforce_policy(policy, subject)

    return [Depends(check)]


async def _enforce_policy(policy: GuardPolicy, subject: object) -> None:
    if not await policy.evaluate_async(subject):
        raise HTTPException(status_code=403, detail="forbidden")


def _default_controller_factory(controller: type[object]) -> object:
    return controller()


def _fastapi_route_options(metadata: RouteMetadata) -> _FastAPIRouteOptions:
    """Translate optional route metadata into FastAPI public keyword arguments."""

    options: _FastAPIRouteOptions = {}
    if metadata.has_response_model:
        options["response_model"] = metadata.response_model
    if metadata.status_code is not None:
        options["status_code"] = metadata.status_code
    if metadata.tags:
        options["tags"] = cast("list[str | Enum]", list(metadata.tags))
    if metadata.summary is not None:
        options["summary"] = metadata.summary
    if metadata.description is not None:
        options["description"] = metadata.description
    if metadata.response_description is not None:
        options["response_description"] = metadata.response_description
    if metadata.operation_id is not None:
        options["operation_id"] = metadata.operation_id
    return options
