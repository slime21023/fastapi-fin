import asyncio

import pytest

from fastapi_fin.application import ApplicationDefinition, Scope, assemble, provide
from fastapi_fin.errors import ResolutionError, RuntimeClosedError
from fastapi_fin.runtime import ApplicationRuntime


def test_runtime_separates_application_and_request_values_and_cleans_up() -> None:
    closed: list[str] = []

    class ApplicationService:
        pass

    class RequestService:
        pass

    definition = ApplicationDefinition(
        providers=(
            provide(
                ApplicationService,
                scope=Scope.APPLICATION,
                disposer=lambda _value: closed.append("application"),
            ),
            provide(
                RequestService,
                scope=Scope.REQUEST,
                disposer=lambda _value: closed.append("request"),
            ),
        ),
    )

    async def scenario() -> None:
        runtime = ApplicationRuntime(assemble(definition))
        await runtime.start()
        application_value = await runtime.resolve(ApplicationService)
        first = runtime.new_request()
        second = runtime.new_request()
        assert await runtime.resolve(ApplicationService, first) is application_value
        assert await runtime.resolve(RequestService, first) is await runtime.resolve(
            RequestService, first
        )
        assert await runtime.resolve(RequestService, first) is not await runtime.resolve(
            RequestService,
            second,
        )
        await first.close()
        await second.close()
        await runtime.stop()

    asyncio.run(scenario())
    assert closed == ["request", "request", "application"]


def test_application_provider_initialization_is_deduplicated_concurrently() -> None:
    calls = 0

    class Service:
        pass

    async def factory() -> Service:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return Service()

    definition = ApplicationDefinition(
        providers=(provide(Service, factory, scope=Scope.APPLICATION),),
    )

    async def scenario() -> None:
        runtime = ApplicationRuntime(assemble(definition))
        await runtime.start()
        values = await asyncio.gather(*(runtime.resolve(Service) for _ in range(20)))
        assert len({id(value) for value in values}) == 1
        await runtime.stop()

    asyncio.run(scenario())
    assert calls == 1


def test_runtime_rejects_invalid_lifecycle_operations_and_factory_failures() -> None:
    class Service:
        pass

    class RequestService:
        pass

    def failing_factory() -> Service:
        raise ValueError("bad factory")

    runtime = ApplicationRuntime(
        assemble(
            ApplicationDefinition(
                providers=(
                    provide(Service, failing_factory, scope=Scope.APPLICATION),
                    provide(RequestService),
                ),
            )
        )
    )

    async def scenario() -> None:
        with pytest.raises(RuntimeClosedError, match="not started"):
            await runtime.resolve(Service)
        await runtime.start()
        with pytest.raises(ResolutionError, match="provider factory failed"):
            await runtime.resolve(Service)
        with pytest.raises(ResolutionError, match="request context"):
            await runtime.resolve(RequestService)
        await runtime.stop()
        with pytest.raises(RuntimeClosedError, match="closed"):
            await runtime.start()

    asyncio.run(scenario())


def test_request_cleanup_continues_after_a_disposer_failure() -> None:
    closed: list[str] = []

    class First:
        pass

    class Second:
        pass

    def fail_disposer(_value: object) -> None:
        closed.append("first")
        raise RuntimeError("cleanup failed")

    definition = ApplicationDefinition(
        providers=(
            provide(First, disposer=fail_disposer),
            provide(Second, disposer=lambda _value: closed.append("second")),
        ),
    )

    async def scenario() -> None:
        runtime = ApplicationRuntime(assemble(definition))
        await runtime.start()
        context = runtime.new_request()
        await runtime.resolve(First, context)
        await runtime.resolve(Second, context)
        with pytest.raises(ExceptionGroup, match="cleanup failed"):
            await context.close()
        assert context.closed
        await runtime.stop()

    asyncio.run(scenario())
    assert closed == ["second", "first"]
