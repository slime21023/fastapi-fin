"""Optional framework-independent event bus."""

from collections.abc import Awaitable, Callable, Iterable
from inspect import isawaitable

from attrs import define, field

from .._validation import callable_validator, normalize_iterable
from ..errors import DefinitionError

EventHandler = Callable[[object], object | Awaitable[object]]


@define(frozen=True, slots=True)
class EventSubscription:
    event_type: type[object]
    handler: EventHandler = field(validator=callable_validator("event handler"))

    def __attrs_post_init__(self) -> None:
        if not isinstance(self.event_type, type):
            raise DefinitionError("event type must be a class")


def _normalize_subscriptions(
    values: Iterable[EventSubscription],
) -> tuple[EventSubscription, ...]:
    normalized = normalize_iterable(values, "event subscriptions")
    if not all(isinstance(item, EventSubscription) for item in normalized):
        raise DefinitionError("event subscriptions contain invalid values")
    return normalized


@define(frozen=True, slots=True)
class EventBus:
    """Persistent event subscriptions with asynchronous publication."""

    subscriptions: tuple[EventSubscription, ...] = field(
        default=(),
        converter=_normalize_subscriptions,
    )

    def subscribe(self, event_type: type[object], handler: EventHandler) -> "EventBus":
        subscription = EventSubscription(event_type, handler)
        if any(
            item.event_type is event_type and item.handler == handler for item in self.subscriptions
        ):
            raise DefinitionError("event handler is already subscribed")
        return EventBus((*self.subscriptions, subscription))

    async def publish(self, event: object) -> None:
        """Publish an event to matching subscribers in registration order."""
        for subscription in self.subscriptions:
            if isinstance(event, subscription.event_type):
                result = subscription.handler(event)
                if isawaitable(result):
                    await result


__all__ = ["EventBus", "EventHandler", "EventSubscription"]
