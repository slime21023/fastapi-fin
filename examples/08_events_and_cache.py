"""Use framework-independent events and the small in-process cache primitive."""

import asyncio

from fastapi_fin.features import CachePolicy, CacheStore, EventBus


async def publish_events() -> list[str]:
    received: list[str] = []

    def record_sync(event: object) -> None:
        received.append(f"sync:{event}")

    async def record_async(event: object) -> None:
        received.append(f"async:{event}")

    bus = EventBus().subscribe(str, record_sync).subscribe(str, record_async)
    await bus.publish("created")
    return received


def main() -> None:
    assert asyncio.run(publish_events()) == ["sync:created", "async:created"]

    cache = CacheStore(CachePolicy(max_entries=2))
    cache.set("first", 1)
    cache.set("second", 2)
    cache.set("third", 3)

    assert cache.get("first") is None
    assert cache.get("second") == 2
    assert cache.get("third") == 3
    print("08_events_and_cache: OK")


if __name__ == "__main__":
    main()
