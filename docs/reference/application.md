# Application definitions

本頁描述 application declaration layer。這一層只建立 immutable definition，不建立
FastAPI app，也不持有 request 或 application runtime state。

## Public types

### Type aliases

| 名稱 | 型別 | 說明 |
| --- | --- | --- |
| `Endpoint` | `Callable[..., object]` | route endpoint callable |
| `ServiceToken` | `type[object] \| str` | provider 的識別 token |
| `ProviderFactory` | `Callable[..., object]` | provider factory，可回傳 awaitable |
| `Disposer` | `Callable[[object], object \| Awaitable[object]]` | provider cleanup callable |
| `LifecycleHook` | `Callable[[], object \| Awaitable[object]]` | startup/shutdown hook |

`ServiceToken` 可以是 class 或非空字串。class token 通常適合 application 內部的 typed
service；字串 token 適合 plugin 或外部整合，但必須在 `provide()` 時明確提供 factory。

## `HttpMethod` 與 `Scope`

```python
from fastapi_fin.application import HttpMethod, Scope
```

`HttpMethod` 是 `StrEnum`，包含 `CONNECT`、`DELETE`、`GET`、`HEAD`、`OPTIONS`、`PATCH`、
`POST`、`PUT` 與 `TRACE`。

`Scope` 是 provider lifetime：

| 值 | 行為 |
| --- | --- |
| `Scope.APPLICATION` | 整個 application runtime 共用一個 instance |
| `Scope.REQUEST` | 每個 request context 建立一個 instance |

## `Inject` 與 `inject()`

```python
class Inject:
    token: ServiceToken


def inject(token: ServiceToken) -> InjectedType: ...
```

`inject()` 回傳 immutable injection marker。它不會立即解析 provider，也不直接依賴
FastAPI；`FastAPIAdapter.create_app()` 會在 compile endpoint 時將 marker 轉成
`fastapi.Depends`。

```python
class TaskService: ...


@router.get("/")
def list_tasks(service: TaskService = inject(TaskService)) -> list[str]:
    return service.list()
```

限制：

- 使用 `inject()` 的 route 必須透過 `FastAPIAdapter.create_app()`。
- 使用 `FastAPIAdapter.mount()` 會得到 `AdapterError`，因為 mount 沒有 runtime。
- marker 的 token 必須在 application definition 中有對應 provider，否則 `assemble()`
  會先拒絕 definition。

## `RouteDefinition`

```python
@define(frozen=True, slots=True)
class RouteDefinition:
    path: str
    endpoint: Endpoint
    methods: tuple[HttpMethod, ...] = (HttpMethod.GET,)
    name: str | None = None
    deprecated: bool = False
    include_in_schema: bool = True
    response_model: object | None = None
    status_code: int | None = None
    tags: tuple[str, ...] = ()
    summary: str | None = None
    description: str | None = None
    response_description: str | None = None
    operation_id: str | None = None
    guards: tuple[GuardDefinition, ...] = ()
    interceptors: tuple[InterceptorDefinition, ...] = ()
```

建構時會：

- 將 path 正規化為 `/` 開頭，拒絕空白、query、fragment 與 null character。
- 將 method 正規化為 `HttpMethod`，去除重複 method。
- 將 tags、guards、interceptors materialize 成 tuple。
- 驗證 `status_code` 位於 `100..599`。
- 驗證 `operation_id` 只有在單一 HTTP method 時使用。
- 保留 endpoint callable 本身，不包裝 endpoint signature。

`RouteDefinition` 不會在建立時驗證 FastAPI response model；response model 會在 Adapter
將 route 加入 FastAPI 時交給 FastAPI 處理。

## `route()`

```python
def route(
    path: str,
    endpoint: Endpoint,
    *,
    methods: str | HttpMethod | Iterable[str | HttpMethod] = HttpMethod.GET,
    name: str | None = None,
    deprecated: bool = False,
    include_in_schema: bool = True,
    response_model: object | None = None,
    status_code: int | None = None,
    tags: Iterable[str] = (),
    summary: str | None = None,
    description: str | None = None,
    response_description: str | None = None,
    operation_id: str | None = None,
    guards: Iterable[GuardDefinition] = (),
    interceptors: Iterable[InterceptorDefinition] = (),
) -> RouteDefinition: ...
```

`route()` 是單一路由的低階 factory。適合：

- 動態產生 route definitions。
- 需要在集中式 assembly 中明確列出 routes。
- 不需要 module-level decorator grouping 的小型 application。

```python
definition = ApplicationDefinition(
    routes=(
        route(
            "/reports/{report_id}",
            read_report,
            methods="GET",
            response_model=ReportView,
            tags=("reports",),
        ),
    ),
)
```

## `ApplicationRouter`

```python
ApplicationRouter(
    prefix: str = "",
    tags: Iterable[str] = (),
    guards: Iterable[GuardDefinition] = (),
    interceptors: Iterable[InterceptorDefinition] = (),
)
```

`ApplicationRouter` 是 declaration-time builder，提供接近 FastAPI `APIRouter` 的
decorator 語法，但不依賴 FastAPI。router 本身可以變動地收集 route；每一個
`RouteDefinition` 以及 router snapshot 都是 immutable。

### Registration methods

```python
router.add_api_route(path, endpoint, *, methods=..., **route_options) -> None
router.api_route(path, *, methods=..., **route_options) -> Callable
router.get(path, **route_options) -> Callable
router.post(path, **route_options) -> Callable
router.put(path, **route_options) -> Callable
router.patch(path, **route_options) -> Callable
router.delete(path, **route_options) -> Callable
router.options(path, **route_options) -> Callable
router.head(path, **route_options) -> Callable
router.trace(path, **route_options) -> Callable
router.connect(path, **route_options) -> Callable
```

所有 decorator method 都接受 `RouteDefinition` 對應的 route options，例如
`response_model`、`status_code`、`tags`、`guards` 與 `interceptors`，並回傳原本的
endpoint callable：

```python
router = ApplicationRouter(prefix="/users", tags=("users",))


@router.get("/{user_id}", summary="Read one user")
def read_user(user_id: int) -> UserView: ...
```

Router-level metadata 會在 registration 時套用到每一條 route：

- tags：`router.tags + route.tags`
- guards：`router.guards + route.guards`
- interceptors：`router.interceptors + route.interceptors`
- path：`router.prefix + route.path`

### `include_router()`

```python
def include_router(
    router: ApplicationRouter,
    *,
    prefix: str = "",
    tags: Iterable[str] = (),
    guards: Iterable[GuardDefinition] = (),
    interceptors: Iterable[InterceptorDefinition] = (),
) -> None: ...
```

`include_router()` 會讀取被 include router 的當下 snapshot，將 include-level metadata
放在外層 metadata 與原 route metadata 之前。之後被 include 的 router 再新增 route，
不會回溯修改已加入的 route。

```python
admin_router = ApplicationRouter(prefix="/admin")
public_router = ApplicationRouter(prefix="/api")

public_router.include_router(
    admin_router,
    prefix="/v1",
    tags=("admin",),
)
```

### `snapshot()` 與 `routes`

```python
router.snapshot() -> tuple[RouteDefinition, ...]
router.routes -> tuple[RouteDefinition, ...]
```

一般 assembly 不需要手動 snapshot：

```python
definition = ApplicationDefinition(routes=router)
```

`ApplicationDefinition` 建構時會將 router source materialize 成固定 tuple。之後對
router 註冊 route 不會改變已建立的 definition。

## `ProviderDefinition` 與 `provide()`

```python
@define(frozen=True, slots=True)
class ProviderDefinition:
    token: ServiceToken
    factory: ProviderFactory
    dependencies: tuple[ServiceToken, ...] = ()
    scope: Scope = Scope.REQUEST
    eager: bool = False
    disposer: Disposer | None = None
```

```python
def provide(
    token: ServiceToken,
    factory: ProviderFactory | None = None,
    *,
    dependencies: Iterable[ServiceToken] = (),
    scope: Scope = Scope.REQUEST,
    eager: bool = False,
    disposer: Disposer | None = None,
) -> ProviderDefinition: ...
```

行為與限制：

- `factory` 可以是同步或 async callable。
- `factory=None` 時，只有 class token 可以省略 factory；系統會使用該 class 本身。
- string token 必須明確提供 factory。
- `dependencies` 會以 positional arguments 傳給 factory，順序依 declaration 保留。
- `eager=True` 只能用於 `Scope.APPLICATION`。
- `disposer` 在 resource 釋放時呼叫；async disposer 會被 await。
- provider token 必須唯一，依賴必須存在，循環依賴由 `assemble()` 拒絕。

```python
class Database: ...


class UserRepository:
    def __init__(self, database: Database) -> None:
        self.database = database


providers = (
    provide(Database, scope=Scope.APPLICATION, eager=True),
    provide(
        UserRepository,
        dependencies=(Database,),
        scope=Scope.REQUEST,
    ),
)
```

## `LifecycleDefinition`

```python
@define(frozen=True, slots=True)
class LifecycleDefinition:
    startup: tuple[LifecycleHook, ...] = ()
    shutdown: tuple[LifecycleHook, ...] = ()
```

```python
lifecycle = LifecycleDefinition(
    startup=(connect_metrics,),
    shutdown=(disconnect_metrics,),
)
```

startup hooks 依 declaration order 執行；shutdown hooks 以反向順序執行。hook 可以同步或
async。若 startup 或 provider eager initialization 失敗，runtime 會嘗試清理已建立資源後
重新拋出原始錯誤。

## `ApplicationDefinition`

```python
@define(frozen=True, slots=True)
class ApplicationDefinition:
    routes: tuple[RouteDefinition, ...] = ()
    providers: tuple[ProviderDefinition, ...] = ()
    guards: tuple[GuardDefinition, ...] = ()
    interceptors: tuple[InterceptorDefinition, ...] = ()
    lifecycle: LifecycleDefinition = field(factory=LifecycleDefinition)
```

`routes` 可以是：

- `RouteDefinition`。
- `ApplicationRouter`。
- route definitions、router sources 的 iterable。

建立 `ApplicationDefinition` 會複製 iterable、驗證 model type，並保存 immutable tuple。
這是 application declaration 與 runtime state 的分界。

## `assemble()`

```python
def assemble(definition: ApplicationDefinition) -> ApplicationModel: ...
```

`assemble()` 建立內部 immutable `ApplicationModel`，並檢查：

- method/path route conflict。
- provider token conflict。
- 缺少 provider dependency。
- circular dependency。
- application-scoped provider 依賴 request-scoped provider。
- endpoint injection marker 找不到 provider。

通常不需要手動呼叫；`FastAPIAdapter.create_app()` 與 `mount()` 都會先 assembly。直接
呼叫適合 unit test 或需要在啟動 FastAPI 前檢查 definition 的工具。

## 完整 declaration 範例

```python
router = ApplicationRouter(prefix="/tasks", tags=("tasks",))


@router.get("/")
def list_tasks(service: TaskService = inject(TaskService)) -> list[TaskView]:
    return service.list()


definition = ApplicationDefinition(
    routes=router,
    providers=(
        provide(Database, scope=Scope.APPLICATION, eager=True),
        provide(TaskService, dependencies=(Database,)),
    ),
    lifecycle=LifecycleDefinition(
        startup=(initialize_metrics,),
        shutdown=(shutdown_metrics,),
    ),
)
```
