import asyncio
from inspect import signature
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

import pytest

from fastapi_fin.core import (
    CachePolicy,
    DeclarationError,
    InterceptorChain,
    InterceptorSpec,
    RegistrationError,
)


def test_interceptor_chain_preserves_endpoint_name_and_order() -> None:
    calls: list[str] = []

    def endpoint(value: int) -> int:
        calls.append("endpoint")
        return value + 1

    def outer(next_call, _args, _kwargs):
        calls.append("outer-before")
        result = next_call()
        calls.append("outer-after")
        return result

    def inner(next_call, _args, _kwargs):
        calls.append("inner-before")
        result = next_call()
        calls.append("inner-after")
        return result

    chain = (
        InterceptorChain()
        .add(InterceptorSpec(name="inner", handler=inner, order=20))
        .add(InterceptorSpec(name="outer", handler=outer, order=10))
    )
    wrapped = chain.apply(endpoint)

    assert getattr(wrapped, "__name__", None) == "endpoint"
    assert signature(wrapped) == signature(endpoint)
    assert wrapped(1) == 2
    assert calls == ["outer-before", "inner-before", "endpoint", "inner-after", "outer-after"]


def test_direct_interceptor_chain_is_normalized_by_order() -> None:
    first = InterceptorSpec(name="first", handler=lambda _next, _args, _kwargs: None, order=20)
    second = InterceptorSpec(name="second", handler=lambda _next, _args, _kwargs: None, order=10)

    chain = InterceptorChain(interceptors=(first, second))

    assert [interceptor.name for interceptor in chain.interceptors] == ["second", "first"]


def test_interceptor_retries_sync_failures() -> None:
    attempts = 0

    def endpoint() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RuntimeError("temporary failure")
        return "ok"

    chain = InterceptorChain().add(
        InterceptorSpec(
            name="retry",
            handler=lambda next_call, _args, _kwargs: next_call(),
            retries=2,
        )
    )

    assert chain.apply(endpoint)() == "ok"
    assert attempts == 3


def test_interceptor_translates_final_sync_failure() -> None:
    chain = InterceptorChain().add(
        InterceptorSpec(
            name="translate",
            handler=lambda next_call, _args, _kwargs: next_call(),
            error_handler=lambda error: {"error": str(error)},
        )
    )

    def endpoint() -> str:
        raise ValueError("invalid input")

    assert chain.apply(endpoint)() == {"error": "invalid input"}


def test_interceptor_translates_final_async_failure_after_retries() -> None:
    attempts = 0

    async def endpoint() -> str:
        nonlocal attempts
        attempts += 1
        raise LookupError("missing")

    async def translate(error: Exception) -> str:
        return f"translated: {error}"

    chain = InterceptorChain().add(
        InterceptorSpec(
            name="translate-async",
            handler=lambda next_call, _args, _kwargs: next_call(),
            retries=2,
            error_handler=translate,
        )
    )

    assert asyncio.run(cast("Coroutine[object, object, object]", chain.apply(endpoint)())) == (
        "translated: missing"
    )
    assert attempts == 3


def test_interceptor_caches_sync_results_by_arguments() -> None:
    calls = 0

    def endpoint(value: int) -> int:
        nonlocal calls
        calls += 1
        return value * 2

    chain = InterceptorChain().add(
        InterceptorSpec(
            name="cache",
            handler=lambda next_call, _args, _kwargs: next_call(),
            cache=CachePolicy(),
        )
    )
    wrapped = chain.apply(endpoint)

    assert wrapped(2) == 4
    assert wrapped(2) == 4
    assert wrapped(3) == 6
    assert calls == 2


def test_interceptor_caches_async_results() -> None:
    calls = 0

    async def endpoint(value: int) -> int:
        nonlocal calls
        calls += 1
        return value + 1

    chain = InterceptorChain().add(
        InterceptorSpec(
            name="async-cache",
            handler=lambda next_call, _args, _kwargs: next_call(),
            cache=CachePolicy(),
        )
    )
    wrapped = cast("Callable[[int], Coroutine[object, object, int]]", chain.apply(endpoint))

    async def run() -> tuple[int, int]:
        return await wrapped(1), await wrapped(1)

    assert asyncio.run(run()) == (2, 2)
    assert calls == 1


def test_interceptor_applies_timeout_to_async_endpoints() -> None:
    async def endpoint() -> str:
        await asyncio.sleep(0.05)
        return "too late"

    chain = InterceptorChain().add(
        InterceptorSpec(
            name="timeout",
            handler=lambda next_call, _args, _kwargs: next_call(),
            timeout=0.001,
        )
    )

    with pytest.raises(TimeoutError):
        asyncio.run(cast("Coroutine[object, object, object]", chain.apply(endpoint)()))


def test_interceptor_rejects_timeout_for_sync_pipeline() -> None:
    chain = InterceptorChain().add(
        InterceptorSpec(
            name="sync-timeout",
            handler=lambda next_call, _args, _kwargs: next_call(),
            timeout=1,
        )
    )

    with pytest.raises(DeclarationError, match="requires an async"):
        chain.apply(lambda: "ok")


def test_interceptor_rejects_dynamically_async_results_in_sync_pipeline() -> None:
    async def translate(_next_call) -> str:
        return "translated"

    def handler(next_call, _args, _kwargs):
        return translate(next_call)

    chain = InterceptorChain().add(InterceptorSpec(name="dynamic-async", handler=handler))

    with pytest.raises(TypeError, match="requires an async pipeline"):
        chain.apply(lambda: "ok")()


def test_interceptor_rejects_invalid_declarations() -> None:
    with pytest.raises(DeclarationError):
        InterceptorSpec(name=" ", handler=lambda _next, _args, _kwargs: None)
    with pytest.raises(DeclarationError):
        InterceptorSpec(
            name="invalid",
            handler=cast("Callable[..., object]", object()),
        )
    with pytest.raises(DeclarationError):
        InterceptorSpec(
            name="invalid-error-handler",
            handler=lambda _next, _args, _kwargs: None,
            error_handler=cast("Callable[[Exception], object]", object()),
        )

    spec = InterceptorSpec(name="duplicate", handler=lambda _next, _args, _kwargs: None)
    with pytest.raises(RegistrationError):
        InterceptorChain(interceptors=(spec, spec))
