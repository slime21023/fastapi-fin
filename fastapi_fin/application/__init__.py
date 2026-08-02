"""Framework-independent declaration and metadata assembly APIs."""

from .compiler import CompiledApplication, CompiledRoute, compile_application
from .decorators import (
    connect,
    controller,
    delete,
    get,
    guard,
    head,
    module,
    options,
    patch,
    post,
    put,
    route,
    trace,
    use_interceptor,
)
from .registry import MetadataRegistry

__all__ = [
    "CompiledApplication",
    "CompiledRoute",
    "MetadataRegistry",
    "compile_application",
    "connect",
    "controller",
    "delete",
    "get",
    "guard",
    "head",
    "module",
    "options",
    "patch",
    "post",
    "put",
    "route",
    "trace",
    "use_interceptor",
]
