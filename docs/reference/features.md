# Features

Features 是可選的 framework-independent primitives。它們可以獨立使用，也可以透過
`ApplicationDefinition` 或 `ApplicationRouter` 組合到 route pipeline。

## Guards

### Types

```python
GuardPredicate = Callable[[object], bool | Awaitable[bool]]
```

### `GuardDefinition`

```python
@define(frozen=True, slots=True)
class GuardDefinition:
    predicate: GuardPredicate
    name: str = "guard"
    priority: int = 0

    async def allows(self, subject: object) -> bool: ...
```

`allows()` 支援 sync/async predicate，但 predicate 的最終回傳值必須是實際的 `bool`；
`1`、`0` 或其他 truthy/falsy object 不會被視為合法 guard result。

```python
def guard(
    predicate: GuardPredicate,
    *,
    name: str = "guard",
    priority: int = 0,
) -> GuardDefinition: ...
```

### `enforce_guards()`

```python
async def enforce_guards(
    guards: Iterable[GuardDefinition],
    subject: object,
) -> None: ...
```

guards 依 `priority` descending 執行。第一個回傳 `False` 的 guard 會 raise
`AccessDeniedError`；之後的 guard 不會執行。predicate 本身的 exception 不會被轉成
authorization denial，而會向上拋出。

```python
admin_guard = guard(
    lambda request: request.user.is_admin,
    name="admin-only",
    priority=100,
)
```

route-level 與 application-level guards 的組合順序為：application guards 先於 route
guards；同一層再依 priority descending 執行。

## Interceptors

### Types

```python
Arguments = tuple[object, ...]
KeywordArguments = dict[str, object]
NextCall = Callable[[Arguments, KeywordArguments], Awaitable[object]]
InterceptorHandler = Callable[
    [NextCall, Arguments, KeywordArguments],
    object | Awaitable[object],
]
```

### `InterceptorDefinition` 與 `interceptor()`

```python
@define(frozen=True, slots=True)
class InterceptorDefinition:
    handler: InterceptorHandler
    name: str = "interceptor"
    priority: int = 0
```

```python
def interceptor(
    handler: InterceptorHandler,
    *,
    name: str = "interceptor",
    priority: int = 0,
) -> InterceptorDefinition: ...
```

handler 可以同步或 async，並且必須決定是否呼叫 `next_call`：

```python
async def audit(next_call, args, kwargs):
    started = monotonic()
    result = await next_call(args, kwargs)
    record_duration(monotonic() - started)
    return result


audit_interceptor = interceptor(audit, name="audit", priority=10)
```

### `execute_interceptors()`

```python
async def execute_interceptors(
    endpoint: Callable[..., object],
    args: tuple[object, ...],
    kwargs: dict[str, object],
    interceptors: Iterable[InterceptorDefinition],
) -> object: ...
```

執行規則：

- priority 以 ascending 排序。
- 低 priority 的 interceptor 是較外層 wrapper。
- handler 沒有呼叫 `next_call` 時，可以短路 endpoint。
- endpoint 與 handler 都可以是 sync 或 async。
- `args` 與 `kwargs` 以 tuple/dict 傳入，不會被 framework wrapper 改寫。

## Events

### `EventSubscription`

```python
@define(frozen=True, slots=True)
class EventSubscription:
    event_type: type[object]
    handler: EventHandler
```

`event_type` 必須是 class；handler 可以是 sync 或 async callable。

### `EventBus`

```python
@define(frozen=True, slots=True)
class EventBus:
    subscriptions: tuple[EventSubscription, ...] = ()

    def subscribe(
        self,
        event_type: type[object],
        handler: EventHandler,
    ) -> "EventBus": ...

    async def publish(self, event: object) -> None: ...
```

`subscribe()` 不修改原 bus，而是回傳新的 immutable bus；相同 event type 與相同 handler
重複訂閱會 raise `DefinitionError`。`publish()` 依 registration order 執行所有符合
`isinstance(event, event_type)` 的 subscribers。

```python
bus = EventBus().subscribe(UserCreated, on_user_created)
await bus.publish(UserCreated(user_id="user-1"))
```

`EventBus` 沒有 queue、retry、delivery persistence 或跨 process transport；需要這些語義
時應接到外部 message broker。

## Configuration

### `SettingDefinition`

```python
@define(frozen=True, slots=True)
class SettingDefinition:
    name: str
    parser: Callable[[object], object]
    required: bool = True
    default: object  # omitted when no default is configured
    sensitive: bool = False
```

規則：

- `name` 必須非空。
- `parser` 必須 callable。
- `required=True` 時不能設定 default。
- `sensitive=True` 只影響 `Configuration.__repr__()` 與 `redacted()`，不會加密值。

### `Configuration.load()`

```python
@define(frozen=True, slots=True)
class Configuration:
    values: Mapping[str, object] = field(factory=dict)
    sensitive_names: frozenset[str] = field(factory=frozenset)

    @classmethod
    def load(
        cls,
        raw: Mapping[str, object],
        settings: tuple[SettingDefinition, ...],
    ) -> "Configuration": ...

    def get(self, name: str) -> object: ...

    def redacted(self) -> dict[str, object]: ...
```

`load()` 會依序處理：

1. 驗證 raw 是 mapping。
2. 驗證設定名稱唯一且沒有 unknown input。
3. 使用 raw value、default 或 required 規則取得 value。
4. 呼叫 parser。
5. 將結果保存為 immutable mapping。

缺少 required setting、unknown setting 或 parser 失敗都會 raise `DefinitionError`。`get()`
查詢未知名稱也會 raise `DefinitionError`，不是回傳 `None`。

```python
settings = (
    SettingDefinition("port", int, default=8000),
    SettingDefinition("database_url", str, sensitive=True),
)
config = Configuration.load(
    {"database_url": "postgresql://..."},
    settings,
)
assert config.get("port") == 8000
assert config.redacted()["database_url"] == "<redacted>"
```

## Cache

### `CachePolicy`

```python
@dataclass(frozen=True, slots=True)
class CachePolicy:
    ttl: float | None = None
    max_entries: int | None = None
```

- `ttl` 必須是 finite positive number；單位為秒。
- `max_entries` 必須是 positive integer。
- `None` 表示不限制該項目。

### `CacheStore`

```python
class CacheStore:
    def __init__(self, policy: CachePolicy | None = None) -> None: ...

    def get(self, key: Hashable) -> object | None: ...

    def set(self, key: Hashable, value: object) -> None: ...

    def clear(self) -> None: ...
```

`CacheStore` 是 thread-safe、in-process、mutable state：

- `get()` 遇到 miss 或 expired entry 回傳 `None`。
- `set()` 在超過 `max_entries` 時移除最早插入的 entry。
- TTL 使用 monotonic clock，不受系統 wall-clock 調整影響。
- key 必須 hashable，否則 raise `DefinitionError`。
- 沒有跨 process、持久化、stampede prevention 或 distributed invalidation。
