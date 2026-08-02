"""Compose user lifespan handlers with FastAPI-Fin runtime lifecycle."""

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI

from ..core.dependency import ContainerRuntime
from ..core.events import ApplicationStarted, ApplicationStopping, EventDispatcher

LifespanHandler = Callable[[FastAPI], AbstractAsyncContextManager[None]]

__all__ = ["LifespanHandler", "compose_lifespan"]


def compose_lifespan(
    user_lifespan: LifespanHandler | None,
    *,
    runtime: ContainerRuntime | None,
    dispatcher: EventDispatcher | None,
) -> LifespanHandler | None:
    """Add runtime startup/shutdown around an optional user lifespan."""

    if dispatcher is None and runtime is None:
        return user_lifespan

    @asynccontextmanager
    async def composed(app: FastAPI):
        started = False
        try:
            if user_lifespan is None:
                if runtime is not None:
                    await runtime.initialize_async()
                if dispatcher is not None:
                    await dispatcher.publish_async(ApplicationStarted())
                    started = True
                yield
            else:
                async with user_lifespan(app):
                    if runtime is not None:
                        await runtime.initialize_async()
                    if dispatcher is not None:
                        await dispatcher.publish_async(ApplicationStarted())
                        started = True
                    yield
        finally:
            try:
                if started and dispatcher is not None:
                    await dispatcher.publish_async(ApplicationStopping())
            finally:
                if runtime is not None:
                    await runtime.close_async()

    return composed
