# 獨立功能

`fastapi_fin.features` 的功能可以獨立使用，不需要建立 FastAPI app，也不會自動接入
`ApplicationDefinition`。這讓它們可以在 application layer 或 unit test 中單獨採用。

## Configuration

使用 `SettingDefinition` 定義 parser、required、default 與 sensitive：

```python
from fastapi_fin.features import Configuration, SettingDefinition


settings = (
    SettingDefinition("port", int),
    SettingDefinition(
        "debug", lambda value: str(value).lower() == "true", required=False, default="false"
    ),
    SettingDefinition("api_key", str, sensitive=True),
)

configuration = Configuration.load(
    {"port": "8080", "api_key": "secret"},
    settings,
)
```

解析後的 values 是 immutable snapshot。`repr(configuration)` 與 `redacted()` 會將
sensitive values 顯示為 `<redacted>`。Configuration 不會自行讀取 environment variable；
呼叫端應先準備 raw mapping。

## EventBus

`EventBus` 使用 immutable subscription snapshot：

```python
from fastapi_fin.features import EventBus


async def handle(event: object) -> None:
    print(event)


bus = EventBus().subscribe(str, handle)
await bus.publish("created")
```

handler 依註冊順序執行，支援同步與非同步 handler。只有符合 `isinstance(event,
event_type)` 的 subscription 會收到事件。

## CacheStore

`CacheStore` 是 thread-safe 的 in-process cache：

```python
from fastapi_fin.features import CachePolicy, CacheStore


cache = CacheStore(CachePolicy(ttl=60, max_entries=100))
cache.set("user:1", {"id": 1})
value = cache.get("user:1")
```

它適合單一 process 的小型 cache，不是 distributed cache，也不會跨 worker 共用。支援
TTL、最大項目數與 `clear()`。
