"""Translate container resolution into FastAPI dependency callables."""

from collections.abc import AsyncIterator, Callable
from functools import wraps
from inspect import Parameter, Signature, isawaitable, signature
from typing import Protocol, cast

from fastapi import Depends, HTTPException

from ..core.dependency import ContainerRuntime, ResolutionContext, ServiceToken
from ..core.errors import ResolutionError
from ..core.metadata import ControllerMetadata, Endpoint
from .errors import AdapterError

__all__ = [
    "build_request_controller_endpoint",
    "controller_dependency",
    "inject",
    "resolve_container_service",
]


class _SignatureEndpoint(Protocol):
    """Callable attribute shape required by FastAPI signature inspection."""

    __signature__: Signature


async def _provide_request_context() -> AsyncIterator[ResolutionContext]:
    context = ResolutionContext()
    try:
        yield context
    finally:
        await context.close_async()


_REQUEST_CONTEXT_DEPENDENCY = Depends(_provide_request_context)


def inject(
    runtime: ContainerRuntime,
    token: ServiceToken,
) -> Callable[..., object]:
    """Build a FastAPI dependency that injects one provider per request."""

    async def resolve(context: ResolutionContext = _REQUEST_CONTEXT_DEPENDENCY) -> object:
        return await resolve_container_service(runtime, token, context)

    return resolve


def controller_dependency(
    runtime: ContainerRuntime,
    controller: type[object],
) -> Callable[..., object]:
    """Build a request-scoped dependency for a container-bound controller."""

    async def resolve(
        context: ResolutionContext = _REQUEST_CONTEXT_DEPENDENCY,
    ) -> object:
        return await resolve_container_service(runtime, controller, context)

    return resolve


async def resolve_container_service(
    runtime: ContainerRuntime,
    token: ServiceToken,
    context: ResolutionContext,
) -> object:
    """Resolve a service while translating domain failures to public HTTP behavior."""

    try:
        return await runtime.resolve_async(token, context)
    except ResolutionError as error:
        raise HTTPException(
            status_code=500,
            detail="dependency resolution failed",
        ) from error


def build_request_controller_endpoint(
    runtime: ContainerRuntime,
    controller_metadata: ControllerMetadata,
    endpoint_template: Endpoint,
    endpoint_name: str,
) -> Endpoint:
    """Wrap a controller method with a public FastAPI dependency marker."""

    controller_dependency_callable = controller_dependency(
        runtime,
        controller_metadata.controller,
    )
    original_signature = signature(endpoint_template)
    parameters = list(original_signature.parameters.values())
    if parameters and parameters[0].name in {"self", "cls"}:
        parameters.pop(0)
    controller_parameter_name = _controller_parameter_name(parameters)
    controller_parameter = Parameter(
        controller_parameter_name,
        kind=Parameter.KEYWORD_ONLY,
        annotation=object,
        default=Depends(controller_dependency_callable),
    )
    parameter_index = next(
        (
            index
            for index, parameter in enumerate(parameters)
            if parameter.kind is Parameter.VAR_KEYWORD
        ),
        len(parameters),
    )
    parameters.insert(parameter_index, controller_parameter)
    endpoint_signature = original_signature.replace(parameters=parameters)

    @wraps(endpoint_template)
    async def request_endpoint(*args: object, **kwargs: object) -> object:
        controller = kwargs.pop(controller_parameter_name)
        endpoint = getattr(controller, endpoint_name, None)
        if endpoint is None:
            raise AdapterError(
                f"controller {controller_metadata.name!r} does not expose endpoint "
                f"{endpoint_name!r}"
            )
        result = endpoint(*args, **kwargs)
        return await result if isawaitable(result) else result

    signature_endpoint = cast("_SignatureEndpoint", request_endpoint)
    signature_endpoint.__signature__ = endpoint_signature
    return cast("Endpoint", signature_endpoint)


def _controller_parameter_name(parameters: list[Parameter]) -> str:
    base_name = "_fastapi_fin_controller"
    existing_names = {parameter.name for parameter in parameters}
    if base_name not in existing_names:
        return base_name
    suffix = 2
    while f"{base_name}_{suffix}" in existing_names:
        suffix += 1
    return f"{base_name}_{suffix}"
