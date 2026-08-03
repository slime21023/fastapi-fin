"""Framework-independent interceptor definitions."""

from collections.abc import Awaitable, Callable, Iterable
from inspect import isawaitable

from attrs import define, field

from .._validation import callable_validator, integer_validator
from ..errors import DefinitionError

Arguments = tuple[object, ...]
KeywordArguments = dict[str, object]
NextCall = Callable[[Arguments, KeywordArguments], Awaitable[object]]
InterceptorHandler = Callable[
    [NextCall, Arguments, KeywordArguments],
    object | Awaitable[object],
]


def _validate_name(_instance: object, _attribute: object, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DefinitionError("interceptor name must not be empty")


@define(frozen=True, slots=True)
class InterceptorDefinition:
    """One middleware-like endpoint interceptor."""

    handler: InterceptorHandler = field(validator=callable_validator("interceptor handler"))
    name: str = field(
        default="interceptor",
        validator=_validate_name,
    )
    priority: int = field(default=0, validator=integer_validator("interceptor priority"))


def interceptor(
    handler: InterceptorHandler,
    *,
    name: str = "interceptor",
    priority: int = 0,
) -> InterceptorDefinition:
    """Create a validated interceptor definition."""
    return InterceptorDefinition(handler=handler, name=name, priority=priority)


async def execute_interceptors(
    endpoint: Callable[..., object],
    args: Arguments,
    kwargs: KeywordArguments,
    interceptors: Iterable[InterceptorDefinition],
) -> object:
    """Execute an endpoint through a stable async interceptor chain."""

    async def terminal(
        call_args: Arguments,
        call_kwargs: KeywordArguments,
    ) -> object:
        result = endpoint(*call_args, **call_kwargs)
        return await result if isawaitable(result) else result

    next_call: NextCall = terminal
    ordered = sorted(interceptors, key=lambda item: item.priority)
    for item in reversed(ordered):
        downstream = next_call

        async def invoke(
            call_args: Arguments,
            call_kwargs: KeywordArguments,
            *,
            current: InterceptorDefinition = item,
            following: NextCall = downstream,
        ) -> object:
            result = current.handler(following, call_args, call_kwargs)
            return await result if isawaitable(result) else result

        next_call = invoke

    return await next_call(args, kwargs)


__all__ = [
    "Arguments",
    "InterceptorDefinition",
    "InterceptorHandler",
    "KeywordArguments",
    "NextCall",
    "execute_interceptors",
    "interceptor",
]
