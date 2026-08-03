"""Framework-independent guard definitions."""

from collections.abc import Awaitable, Callable, Iterable
from inspect import isawaitable

from attrs import define, field

from .._validation import callable_validator, integer_validator
from ..errors import AccessDeniedError, DefinitionError

GuardPredicate = Callable[[object], bool | Awaitable[bool]]


def _validate_name(_instance: object, _attribute: object, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DefinitionError("guard name must not be empty")


@define(frozen=True, slots=True)
class GuardDefinition:
    """One authorization predicate evaluated against a request subject."""

    predicate: GuardPredicate = field(validator=callable_validator("guard predicate"))
    name: str = field(default="guard", validator=_validate_name)
    priority: int = field(default=0, validator=integer_validator("guard priority"))

    async def allows(self, subject: object) -> bool:
        """Evaluate the predicate and reject non-boolean results."""
        result = self.predicate(subject)
        if isawaitable(result):
            result = await result
        if type(result) is not bool:
            raise DefinitionError(f"guard {self.name!r} must return bool")
        return result


def guard(
    predicate: GuardPredicate,
    *,
    name: str = "guard",
    priority: int = 0,
) -> GuardDefinition:
    """Create a validated guard definition."""
    return GuardDefinition(predicate=predicate, name=name, priority=priority)


async def enforce_guards(
    guards: Iterable[GuardDefinition],
    subject: object,
) -> None:
    """Evaluate guards in descending priority order."""
    ordered = sorted(guards, key=lambda item: item.priority, reverse=True)
    for item in ordered:
        if not await item.allows(subject):
            raise AccessDeniedError(item.name)


__all__ = ["GuardDefinition", "GuardPredicate", "enforce_guards", "guard"]
