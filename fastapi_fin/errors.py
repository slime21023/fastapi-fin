"""Public contract composition and integration errors."""


class FastAPIFinError(Exception):
    """Base class for all FastAPI-Fin errors."""


class DefinitionError(FastAPIFinError):
    """Raised when a definition contains an invalid value."""


class AssemblyError(FastAPIFinError):
    """Raised when modules cannot form a valid dependency graph."""


class AdapterError(FastAPIFinError):
    """Raised when FastAPI boundary configuration is invalid."""


__all__ = [
    "AdapterError",
    "AssemblyError",
    "DefinitionError",
    "FastAPIFinError",
]
