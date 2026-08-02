"""FastAPI integration boundary for FastAPI-Fin."""

from .app import CompiledRoute, FastAPIAdapter, LifespanHandler, inject
from .errors import AdapterError

__all__ = [
    "AdapterError",
    "CompiledRoute",
    "FastAPIAdapter",
    "LifespanHandler",
    "inject",
]
