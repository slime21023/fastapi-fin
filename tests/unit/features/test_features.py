import asyncio
from typing import Any, cast

import pytest

from fastapi_fin.errors import AccessDeniedError, DefinitionError
from fastapi_fin.features import (
    CachePolicy,
    CacheStore,
    Configuration,
    EventBus,
    GuardDefinition,
    GuardPredicate,
    InterceptorDefinition,
    SettingDefinition,
    enforce_guards,
    execute_interceptors,
)


def test_guard_rejects_non_boolean_predicates_and_denies_access() -> None:
    async def scenario() -> None:
        with pytest.raises(DefinitionError, match="must return bool"):
            await GuardDefinition(cast("GuardPredicate", lambda _subject: 1)).allows(None)
        with pytest.raises(AccessDeniedError):
            await enforce_guards((GuardDefinition(lambda _subject: False),), None)

    asyncio.run(scenario())


def test_interceptors_execute_by_priority_around_endpoint() -> None:
    events: list[str] = []

    async def outer(next_call, args, kwargs):
        events.append("outer-before")
        result = await next_call(args, kwargs)
        events.append("outer-after")
        return result

    async def inner(next_call, args, kwargs):
        events.append("inner-before")
        result = await next_call(args, kwargs)
        events.append("inner-after")
        return result

    async def scenario() -> object:
        return await execute_interceptors(
            lambda value: value + 1,
            (1,),
            {},
            (
                InterceptorDefinition(inner, priority=10),
                InterceptorDefinition(outer, priority=0),
            ),
        )

    assert asyncio.run(scenario()) == 2
    assert events == ["outer-before", "inner-before", "inner-after", "outer-after"]


def test_configuration_redacts_sensitive_values_and_event_bus_is_persistent() -> None:
    settings = (
        SettingDefinition("port", int),
        SettingDefinition("secret", str, sensitive=True),
    )
    config = Configuration.load({"port": "8000", "secret": "hidden"}, settings)
    assert config.get("port") == 8000
    assert config.redacted()["secret"] == "<redacted>"
    assert "hidden" not in repr(config)

    first = EventBus()
    second = first.subscribe(str, lambda _event: None)
    assert first.subscriptions == ()
    assert len(second.subscriptions) == 1


def test_configuration_is_an_immutable_snapshot() -> None:
    raw = {"port": "8000"}
    config = Configuration.load(raw, (SettingDefinition("port", int),))

    raw["port"] = "9000"
    assert config.get("port") == 8000
    with pytest.raises(TypeError):
        cast("Any", config.values)["port"] = 9000


def test_configuration_rejects_invalid_inputs() -> None:
    with pytest.raises(DefinitionError, match="missing"):
        Configuration.load({}, (SettingDefinition("required", str),))
    with pytest.raises(DefinitionError, match="unknown"):
        Configuration.load({"other": "value"}, (SettingDefinition("required", str),))
    with pytest.raises(DefinitionError, match="invalid"):
        Configuration.load({"port": "bad"}, (SettingDefinition("port", int),))
    with pytest.raises(DefinitionError, match="unique"):
        Configuration.load(
            {},
            (SettingDefinition("value", str, required=False), SettingDefinition("value", str)),
        )


def test_event_bus_publishes_sync_and_async_handlers_and_rejects_duplicates() -> None:
    events: list[str] = []

    async def scenario() -> None:
        async def async_handler(event: object) -> None:
            events.append(f"async:{event}")

        def sync_handler(event: object) -> None:
            events.append(f"sync:{event}")

        bus = EventBus().subscribe(str, sync_handler).subscribe(str, async_handler)
        await bus.publish("created")
        with pytest.raises(DefinitionError, match="already subscribed"):
            bus.subscribe(str, sync_handler)

    asyncio.run(scenario())
    assert events == ["sync:created", "async:created"]


def test_cache_validates_policy_and_supports_expiration_and_eviction() -> None:
    with pytest.raises(DefinitionError, match="finite"):
        CachePolicy(ttl=float("nan"))
    with pytest.raises(DefinitionError, match="positive"):
        CachePolicy(max_entries=0)

    store = CacheStore(CachePolicy(max_entries=1))
    store.set("first", 1)
    store.set("second", 2)
    assert store.get("first") is None
    assert store.get("second") == 2
    with pytest.raises(DefinitionError, match="hashable"):
        store.get([])  # type: ignore[arg-type]
    store.clear()
    assert store.get("second") is None
