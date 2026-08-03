"""Optional framework-independent features."""

from .cache import CachePolicy, CacheStore
from .config import Configuration, SettingDefinition
from .events import EventBus, EventHandler, EventSubscription
from .guards import GuardDefinition, GuardPredicate, enforce_guards, guard
from .interceptors import (
    InterceptorDefinition,
    InterceptorHandler,
    execute_interceptors,
    interceptor,
)

__all__ = [
    "CachePolicy",
    "CacheStore",
    "Configuration",
    "EventBus",
    "EventHandler",
    "EventSubscription",
    "GuardDefinition",
    "GuardPredicate",
    "InterceptorDefinition",
    "InterceptorHandler",
    "SettingDefinition",
    "enforce_guards",
    "execute_interceptors",
    "guard",
    "interceptor",
]
