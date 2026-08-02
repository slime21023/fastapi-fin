import asyncio
from typing import cast

import pytest

from fastapi_fin.core import (
    DeclarationError,
    EventDescriptor,
    EventDispatcher,
    EventSubscription,
    RegistrationError,
)


class UserCreated:
    def __init__(self, user_id: int) -> None:
        self.user_id = user_id


def test_event_dispatcher_is_persistent_and_type_aware() -> None:
    received: list[int] = []

    def handler(event: UserCreated) -> None:
        received.append(event.user_id)

    initial = EventDispatcher()
    updated = initial.subscribe(UserCreated, handler)

    assert initial.snapshot.subscriptions == ()
    assert updated.publish(UserCreated(7)) == (None,)
    assert received == [7]


def test_event_dispatcher_awaits_async_handlers() -> None:
    received: list[int] = []

    async def handler(event: UserCreated) -> int:
        received.append(event.user_id)
        return event.user_id

    dispatcher = EventDispatcher().subscribe(UserCreated, handler)

    assert asyncio.run(dispatcher.publish_async(UserCreated(8))) == (8,)
    assert received == [8]


def test_event_descriptor_normalizes_before_handler_delivery() -> None:
    received: list[int] = []

    def normalize(event: object) -> object:
        assert isinstance(event, UserCreated)
        return UserCreated(max(event.user_id, 0))

    def handler(event: UserCreated) -> None:
        received.append(event.user_id)

    descriptor = EventDescriptor(event_type=UserCreated, normalizer=normalize)
    dispatcher = EventDispatcher().subscribe(descriptor, handler)

    dispatcher.publish(UserCreated(-1))

    assert received == [0]
    assert dispatcher.snapshot.subscriptions[0].descriptor == descriptor


def test_event_async_dispatch_awaits_async_normalizer_and_handler() -> None:
    received: list[int] = []

    async def normalize(event: object) -> object:
        assert isinstance(event, UserCreated)
        await asyncio.sleep(0)
        return UserCreated(event.user_id + 1)

    async def handler(event: UserCreated) -> int:
        received.append(event.user_id)
        return event.user_id

    descriptor = EventDescriptor(event_type=UserCreated, normalizer=normalize)
    dispatcher = EventDispatcher().subscribe(descriptor, handler)

    assert asyncio.run(dispatcher.publish_async(UserCreated(8))) == (9,)
    assert received == [9]


def test_event_sync_dispatch_rejects_async_normalizer() -> None:
    async def normalize(event: object) -> object:
        return event

    descriptor = EventDescriptor(event_type=UserCreated, normalizer=normalize)
    dispatcher = EventDispatcher().subscribe(descriptor, lambda _event: None)

    with pytest.raises(TypeError, match="normalize_async"):
        dispatcher.publish(UserCreated(1))


def test_event_descriptor_rejects_invalid_normalized_values() -> None:
    descriptor = EventDescriptor(
        event_type=UserCreated,
        normalizer=lambda _event: "not-an-event",
    )
    dispatcher = EventDispatcher().subscribe(descriptor, lambda _event: None)

    with pytest.raises(DeclarationError, match="must return an instance"):
        dispatcher.publish(UserCreated(1))

    with pytest.raises(DeclarationError, match="must be an instance"):
        descriptor.normalize(object())


def test_event_subscription_rejects_descriptor_type_mismatch() -> None:
    class OtherEvent:
        pass

    with pytest.raises(RegistrationError, match="must match"):
        EventSubscription(
            event_type=UserCreated,
            handler=lambda _event: None,
            descriptor=EventDescriptor(event_type=OtherEvent),
        )
    with pytest.raises(RegistrationError, match="must be an EventDescriptor"):
        EventSubscription(
            event_type=UserCreated,
            handler=lambda _event: None,
            descriptor=cast("EventDescriptor", object()),
        )


def test_event_sync_dispatch_closes_async_handlers() -> None:
    async def handler(_event: UserCreated) -> None:
        return None

    dispatcher = EventDispatcher().subscribe(UserCreated, handler)

    with pytest.raises(TypeError, match="publish_async"):
        dispatcher.publish(UserCreated(9))


def test_event_dispatcher_unsubscribe_returns_new_snapshot() -> None:
    received: list[int] = []

    def handler(event: UserCreated) -> None:
        received.append(event.user_id)

    initial = EventDispatcher()
    subscribed = initial.subscribe(UserCreated, handler)
    unsubscribed = subscribed.unsubscribe(UserCreated, handler)

    assert initial.snapshot.version == 0
    assert subscribed.snapshot.version == 1
    assert unsubscribed.snapshot.version == 2
    assert unsubscribed.publish(UserCreated(1)) == ()
    assert received == []
    with pytest.raises(RegistrationError):
        unsubscribed.unsubscribe(UserCreated, handler)
