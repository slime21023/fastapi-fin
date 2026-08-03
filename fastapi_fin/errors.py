"""Public error types for FastAPI-Fin 1.0.0."""


class FastAPIFinError(Exception):
    """Base class for all FastAPI-Fin errors."""


class DefinitionError(FastAPIFinError):
    """Raised when a definition contains an invalid value."""


class AssemblyError(FastAPIFinError):
    """Raised when definitions cannot form a valid application model."""


class ResolutionError(FastAPIFinError):
    """Raised when a provider cannot be resolved."""


class RuntimeClosedError(ResolutionError):
    """Raised when an application or request runtime is already closed."""


class AccessDeniedError(FastAPIFinError):
    """Raised when a guard rejects a request."""


class AdapterError(FastAPIFinError):
    """Raised when FastAPI boundary configuration is invalid."""


__all__ = [
    "AccessDeniedError",
    "AdapterError",
    "AssemblyError",
    "DefinitionError",
    "FastAPIFinError",
    "ResolutionError",
    "RuntimeClosedError",
]
