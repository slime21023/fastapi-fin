"""Typed event subscriptions and dispatch independent from FastAPI."""

from collections.abc import Awaitable, Callable
from inspect import isawaitable, iscoroutine
from typing import TypeVar, cast

from attrs import evolve, field, frozen

from ..errors import DeclarationError, RegistrationError
from ..types import _validate_integer, _validate_nonnegative_integer

EventType = type[object]
EventHandler = Callable[[object], object]
EventNormalizer = Callable[[object], object | Awaitable[object]]
EventT = TypeVar("EventT")


def _validate_event_type(_instance: object, _attribute: object, event_type: EventType) -> None:
    if not isinstance(event_type, type):
        raise RegistrationError("event_type must be a class")


def _validate_handler(_instance: object, _attribute: object, handler: EventHandler) -> None:
    if not callable(handler):
        raise RegistrationError("event handler must be callable")


def _validate_normalizer(
    _instance: object,
    _attribute: object,
    normalizer: EventNormalizer,
) -> None:
    if not callable(normalizer):
        raise RegistrationError("event normalizer must be callable")


def _validate_descriptor(
    _instance: object,
    _attribute: object,
    descriptor: "EventDescriptor | None",
) -> None:
    if descriptor is not None and not isinstance(descriptor, EventDescriptor):
        raise RegistrationError("event descriptor must be an EventDescriptor")


def _identity_event(event: object) -> object:
    return event


@frozen(slots=True, kw_only=True)
class EventDescriptor:
    """Immutable event type and normalization contract."""

    event_type: EventType = field(validator=_validate_event_type)
    normalizer: EventNormalizer = field(
        default=_identity_event,
        validator=_validate_normalizer,
    )

    def normalize(self, event: object) -> object:
        """Validate and normalize one event before delivering it to handlers."""
        if not isinstance(event, self.event_type):
            raise DeclarationError(f"event must be an instance of {self.event_type.__name__}")
        try:
            normalized = self.normalizer(event)
        except DeclarationError:
            raise
        except Exception as error:
            raise DeclarationError("event normalization failed") from error
        if isawaitable(normalized):
            if iscoroutine(normalized):
                normalized.close()
            raise TypeError("async event normalizers require normalize_async")
        return _validate_normalized_event(self.event_type, normalized)

    async def normalize_async(self, event: object) -> object:
        """Validate and normalize an event, awaiting an asynchronous normalizer."""
        if not isinstance(event, self.event_type):
            raise DeclarationError(f"event must be an instance of {self.event_type.__name__}")
        try:
            normalized = self.normalizer(event)
            normalized = await normalized if isawaitable(normalized) else normalized
        except DeclarationError:
            raise
        except Exception as error:
            raise DeclarationError("event normalization failed") from error
        return _validate_normalized_event(self.event_type, normalized)


def _validate_normalized_event(event_type: EventType, normalized: object) -> object:
    if not isinstance(normalized, event_type):
        raise DeclarationError("event normalizer must return an instance of the event type")
    return normalized


@frozen(slots=True, kw_only=True)
class ApplicationStarted:
    """Lifecycle event emitted after the application starts."""


@frozen(slots=True, kw_only=True)
class ApplicationStopping:
    """Lifecycle event emitted before the application stops."""


@frozen(slots=True, kw_only=True)
class EventSubscription:
    """Immutable subscription for one event type."""

    event_type: EventType = field(validator=_validate_event_type)
    handler: EventHandler = field(validator=_validate_handler)
    priority: int = field(default=0, validator=_validate_integer)
    descriptor: EventDescriptor | None = field(
        default=None,
        repr=False,
        validator=_validate_descriptor,
    )

    def __attrs_post_init__(self) -> None:
        if self.descriptor is None:
            object.__setattr__(self, "descriptor", EventDescriptor(event_type=self.event_type))
        elif self.descriptor.event_type is not self.event_type:
            raise RegistrationError("event descriptor type must match event_type")

    def normalize(self, event: object) -> object:
        """Normalize an event using this subscription's descriptor."""
        descriptor = self.descriptor
        if descriptor is None:
            raise RegistrationError("event subscription descriptor is not initialized")
        return descriptor.normalize(event)

    async def normalize_async(self, event: object) -> object:
        """Asynchronously normalize an event using this subscription's descriptor."""
        descriptor = self.descriptor
        if descriptor is None:
            raise RegistrationError("event subscription descriptor is not initialized")
        return await descriptor.normalize_async(event)


Subscription = EventSubscription
EventSource = EventType | EventDescriptor


def _normalize_subscriptions(
    values: tuple[EventSubscription, ...],
) -> tuple[EventSubscription, ...]:
    normalized = tuple(values)
    if not all(isinstance(subscription, EventSubscription) for subscription in normalized):
        raise RegistrationError("subscriptions must be EventSubscription instances")
    return normalized


@frozen(slots=True, kw_only=True)
class SubscriptionSnapshot:
    """Persistent collection of event subscriptions."""

    subscriptions: tuple[EventSubscription, ...] = field(
        factory=tuple,
        converter=_normalize_subscriptions,
    )
    version: int = field(default=0, validator=_validate_nonnegative_integer)

    def subscribe(
        self,
        event_type: type[EventT] | EventDescriptor,
        handler: Callable[[EventT], object],
        *,
        priority: int = 0,
    ) -> "SubscriptionSnapshot":
        """Return a new snapshot with a subscription."""
        descriptor = (
            event_type
            if isinstance(event_type, EventDescriptor)
            else EventDescriptor(event_type=event_type)
        )
        if any(
            item.event_type is descriptor.event_type and _same_handler(item.handler, handler)
            for item in self.subscriptions
        ):
            raise RegistrationError("event handler is already subscribed")
        subscription = EventSubscription(
            event_type=descriptor.event_type,
            handler=cast("EventHandler", handler),
            priority=priority,
            descriptor=descriptor,
        )
        return evolve(
            self,
            subscriptions=(*self.subscriptions, subscription),
            version=self.version + 1,
        )

    def unsubscribe(
        self,
        event_type: EventSource,
        handler: EventHandler,
    ) -> "SubscriptionSnapshot":
        """Return a new snapshot without one subscription."""
        normalized_event_type = (
            event_type.event_type if isinstance(event_type, EventDescriptor) else event_type
        )
        remaining = tuple(
            item
            for item in self.subscriptions
            if not (
                item.event_type is normalized_event_type and _same_handler(item.handler, handler)
            )
        )
        if len(remaining) == len(self.subscriptions):
            raise RegistrationError("event handler is not subscribed")
        return evolve(self, subscriptions=remaining, version=self.version + 1)


@frozen(slots=True, kw_only=True)
class EventDispatcher:
    """Immutable subscription state with synchronous and asynchronous dispatch."""

    snapshot: SubscriptionSnapshot = field(factory=SubscriptionSnapshot)

    def subscribe(
        self,
        event_type: type[EventT] | EventDescriptor,
        handler: Callable[[EventT], object],
        *,
        priority: int = 0,
    ) -> "EventDispatcher":
        """Return a dispatcher with one additional subscription."""
        return evolve(
            self,
            snapshot=self.snapshot.subscribe(event_type, handler, priority=priority),
        )

    def unsubscribe(
        self,
        event_type: EventSource,
        handler: Callable[[EventT], object],
    ) -> "EventDispatcher":
        """Return a dispatcher without one existing subscription."""
        return evolve(
            self,
            snapshot=self.snapshot.unsubscribe(event_type, cast("EventHandler", handler)),
        )

    def publish(self, event: object) -> tuple[object, ...]:
        """Dispatch an event to synchronous handlers."""
        results: list[object] = []
        for subscription in self._matching(event):
            result = subscription.handler(subscription.normalize(event))
            if isawaitable(result):
                if iscoroutine(result):
                    result.close()
                raise TypeError("async event handlers require publish_async")
            results.append(result)
        return tuple(results)

    async def publish_async(self, event: object) -> tuple[object, ...]:
        """Dispatch an event and await handlers when necessary."""
        results: list[object] = []
        for subscription in self._matching(event):
            result = subscription.handler(await subscription.normalize_async(event))
            results.append(await result if isawaitable(result) else result)
        return tuple(results)

    def _matching(self, event: object) -> tuple[EventSubscription, ...]:
        return tuple(
            sorted(
                (
                    subscription
                    for subscription in self.snapshot.subscriptions
                    if isinstance(event, subscription.event_type)
                ),
                key=lambda item: -item.priority,
            )
        )


def _same_handler(left: object, right: object) -> bool:
    if left is right:
        return True
    left_owner = getattr(left, "__self__", None)
    right_owner = getattr(right, "__self__", None)
    left_function = getattr(left, "__func__", None)
    right_function = getattr(right, "__func__", None)
    return (
        left_owner is not None
        and left_owner is right_owner
        and left_function is not None
        and left_function is right_function
    )
