"""Exceptions raised by framework-independent FastAPI-Fin code."""


class FastAPIFinError(Exception):
    """Base class for all public FastAPI-Fin errors."""


class DeclarationError(FastAPIFinError):
    """Raised when a decorator or declaration contains invalid input."""


class RegistrationError(FastAPIFinError):
    """Raised when a valid declaration cannot be registered."""


class ResolutionError(FastAPIFinError):
    """Raised when a dependency or runtime value cannot be resolved."""
