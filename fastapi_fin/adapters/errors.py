"""Errors raised while translating FastAPI-Fin into FastAPI."""

from ..core.errors import FastAPIFinError


class AdapterError(FastAPIFinError):
    """Invalid FastAPI adapter configuration or integration state."""


__all__ = ["AdapterError"]
