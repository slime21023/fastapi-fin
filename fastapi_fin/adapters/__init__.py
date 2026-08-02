"""FastAPI integration boundary for FastAPI-Fin."""

from .app import CompiledRoute, FastAPIAdapter, LifespanHandler, container_dependency
from .errors import AdapterError

__all__ = [
    "AdapterError",
    "CompiledRoute",
    "FastAPIAdapter",
    "LifespanHandler",
    "container_dependency",
]
