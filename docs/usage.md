# FastAPI-Fin 使用方式

## 開發環境

專案使用 `uv` 管理虛擬環境與 lockfile：

```powershell
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest
```

提交前會透過 pre-commit 執行格式、lint 與型別檢查；push 前另外執行快速測試。

## 路由與模組宣告

應用層只需要使用 FastAPI-Fin 的宣告器，核心 metadata 不依賴 FastAPI：

```python
from fastapi import FastAPI

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationRegistry, controller, get, module


@controller(prefix="/users")
class UserController:
    @get("/{user_id}")
    def get_user(self, user_id: int) -> dict[str, int]:
        return {"user_id": user_id}


@module(prefix="/v1", controllers=(UserController,))
class ApiModule:
    pass


registry = ApplicationRegistry().module(ApiModule)
app = FastAPI(title="My FastAPI app")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


FastAPIAdapter(app).include(registry)
```

FastAPI 仍然是 application 的主要入口；FastAPI-Fin 只負責將宣告式 routes 掛載到既有
app。原生 FastAPI routes、middleware、OpenAPI 與 Pydantic 行為仍可照常使用。
`include()` 不會修改既有 app 的 lifespan；若 `ApplicationRegistry` 含有 providers 或
配置了 `EventDispatcher`，請使用 `create_app()`，以確保 startup/shutdown 初始化與 cleanup
正確執行。

若需要在不啟動 FastAPI 的情況下檢查組裝結果，可以使用 framework-independent
compiler。Adapter 會在內部使用相同的 compiler，再把結果轉譯成 `APIRouter`：

```python
from fastapi_fin import CompiledApplication, compile_application

compiled: CompiledApplication = compile_application(
    registry,
    endpoint_resolver=lambda _controller, route: route.endpoint,
)
assert compiled.routes[0].metadata.path == "/api/users/{user_id}"
```

Compiler 會建立新的 immutable `CompiledApplication`，固定 registry version、全域
Guard 與 Interceptor 的合併結果；endpoint resolver 留給 Adapter 或其他框架邊界
處理，因此 compiler 本身不會 import FastAPI。

除了 `get` 與 `post` 外，也提供 `put`、`patch`、`delete`、`head`、`options`、`connect` 與 `trace`；需要一次宣告多個 method 時可直接使用 `route(..., methods=[...])`。

Route decorator 也接受 framework-independent 的 OpenAPI／HTTP metadata；Adapter 會
將它們轉譯成 FastAPI public route options：

```python
@get(
    "/{user_id}",
    response_model=UserResponse,
    status_code=200,
    tags=("users",),
    summary="Get user",
    operation_id="get-user",
)
def get_user(self, user_id: int) -> UserResponse:
    return UserResponse(user_id=user_id)
```

支援的 options 包含 `response_model`、`status_code`、`tags`、`summary`、
`description`、`response_description` 與 `operation_id`；未指定的值不會覆蓋
FastAPI 依 endpoint signature 推導的預設行為。

### Typed events

事件訂閱可直接使用 event type，也可以用 immutable `EventDescriptor` 集中處理
型別檢查與 normalization：

```python
from attrs import frozen

from fastapi_fin import EventDescriptor, EventDispatcher


@frozen
class UserCreated:
    user_id: int


def normalize_user_created(event: object) -> object:
    if not isinstance(event, UserCreated) or event.user_id <= 0:
        raise ValueError("user_id must be positive")
    return event


descriptor = EventDescriptor(
    event_type=UserCreated,
    normalizer=normalize_user_created,
)
dispatcher = EventDispatcher().subscribe(descriptor, lambda event: print(event.user_id))
```

normalizer 可以是同步或非同步 callable；`publish_async()` 會等待非同步 normalizer。
同步 `publish()` 遇到非同步 normalizer 時會明確要求改用 `normalize_async`／
`publish_async`。normalizer 若拋出錯誤或回傳錯誤型別，dispatch 會以 framework-independent
`DeclarationError` 統一拒絕，不會將未驗證的 payload 傳給 handler。

模組可以巢狀組合。模組前綴、Guard 與 Interceptor 會依照「父模組 → 子模組 → Controller → 路由」順序合併；組合結果會建立新的 attrs metadata，不會修改原始宣告。

Guard predicate 必須回傳真正的 `bool`；sync／async predicate 回傳其他 truthy 或
falsy 值都會被拒絕，避免授權條件意外放行。

Interceptor 可設定 retry、timeout、`CachePolicy` 與 framework-independent 的 `error_handler`；錯誤處理器只在 retry 次數耗盡後執行，並可回傳替代結果或拋出 domain exception。Timeout 只適用於 async endpoint 或 async interceptor handler；若套用到純同步 pipeline，會在組裝時明確失敗。Cache state 只存在於編譯後 endpoint 的 execution runtime，不會回寫 immutable metadata。

若同步 handler 在執行期間動態回傳 coroutine，Interceptor 會拒絕該結果並關閉 coroutine，避免未 await 的 async 工作穿透同步 pipeline。

retry、timeout、cache TTL、priority 與 snapshot version 都會在 attrs value 建構時
嚴格驗證；`bool`、非整數 version，以及 `nan`／`inf` timeout 或 TTL 會立即拒絕。

`CacheStore` 的 execution state 會保護同步 lookup、store 與 eviction；因此同步 endpoint
在 thread pool 中併發執行時，不會同時修改內部 cache mapping。

`ApplicationRegistry` 中的 Controller 會在 Adapter 建立 runtime 時自動成為 request-scoped
provider，並在每次 request 中透過 FastAPI dependency 解析。只有需要特殊 scope 或 factory
時才需明確 `.provide(Controller)`；Controller 建構子所依賴的 service 會共用同一個 request
context。

Container factory 的 dependency annotation 支援 `Annotated[Service, ...]`；DI 會使用
第一個 type 或 string token，其他 metadata 可由應用層自行使用：

```python
from typing import Annotated


class UserService:
    def __init__(self, database: Annotated[Database, "primary"]) -> None:
        self.database = database
```

若 request/transient service 提供 `close()` 或 `aclose()`，Adapter 會在 request 結束時以反向建立順序釋放；singleton resource 則在 application lifespan shutdown 時釋放。

在 framework-independent code 中，也可以使用 `ResolutionContext` 的 `with` 或
`async with`，讓 request/transient resource 在離開區塊時自動釋放：

```python
with ResolutionContext() as context:
    service = runtime.resolve(UserService, context)
```

若 context 內含 async-only resource，請使用 `async with`；同步 cleanup 會保留 resource
state 並明確要求改用 `close_async()`，避免錯誤路徑遺失 cleanup reference。

若 request-time provider resolution 失敗，Adapter 會回傳不含內部 provider graph
細節的 `500 dependency resolution failed`；core 層仍保留原始 `ResolutionError`
供非 HTTP 使用者處理。

標記為 `lazy=False` 的 singleton 會在 Adapter lifespan startup 時初始化；若 factory 是 async callable，也會由 startup 正確等待完成。

Sync／async lazy singleton 在並發 request 下只會初始化一次；其他解析會等待同一個
factory 完成後共享結果，也涵蓋同步 endpoint 所在的 thread pool。這個並發控制屬於
`ContainerRuntime` 的 execution state，不會修改 immutable provider registry。

設定載入後會保留不可變的 `SettingSpec` 定義；透過 `ConfigSnapshot.replace()` 更新值時，新的值會再次通過原 parser，避免動態更新繞過型別轉換與輸入驗證。

Optional setting 可以在 `SettingSpec` 提供 `default`；缺少 raw input 時，default 仍會
經過同一個 parser：

```python
spec = SettingSpec(name="port", parser=int, required=False, default="8000")
config = ConfigSnapshot.load({}, (spec,))
assert config.get("port") == 8000
```

Parser 發生一般執行期錯誤時，`load()` 與 `replace()` 都會統一拋出
`DeclarationError("invalid configuration setting")`，不會暴露 parser 內部細節。

標記為 `sensitive=True` 的設定會在 `redacted()` 與 `ConfigSnapshot` 的 `repr()` 中
以 `<redacted>` 顯示，避免診斷輸出洩漏原始值。

Provider registration 的推薦流程是「建立 application registry → provide service → 傳給
Adapter」；class token 可以省略 factory，scope 使用 `Scope` 表達：

```python
from fastapi_fin import ApplicationRegistry, Scope

registry = (
    ApplicationRegistry()
    .module(ApiModule)
    .provide(Database, scope=Scope.SINGLETON)
    .provide(UserService)
)
app = FastAPIAdapter.create_app(registry)
```

Route 若需要直接取得 Provider，使用 `dependency()` 建立 FastAPI 原生的
`Depends` marker。它會從目前的 FastAPI app 取得唯一的 application runtime，不需要
建立或傳遞 `ContainerRuntime`：

```python
from fastapi import Depends
from fastapi_fin import ApplicationRegistry, dependency


class CurrentUser:
    pass


registry = ApplicationRegistry().provide(CurrentUser)
current_user = Depends(dependency(CurrentUser))
```

因此 Provider 必須和使用它的 Controller 一起註冊在同一個 `ApplicationRegistry`，再由
`FastAPIAdapter.create_app(registry)` 建立 app；這能確保 Singleton 與 resource cleanup
都由同一個 FastAPI lifespan 管理。

## 開發原則

- `fastapi_fin.core` 僅依賴標準函式庫與 `attrs`，不可 import FastAPI、Starlette 或 Pydantic。
- 只有 `fastapi_fin.adapters` 呼叫 FastAPI 公開 API。
- Adapter 內部依責任拆分為 `app.py`、`router.py`、`dependencies.py` 與 `lifespan.py`；
  Adapter implementation 直接位於 `fastapi_fin.adapters`，不再使用巢狀的 FastAPI package。
- provider registry、metadata、policy 與 subscription 都以 immutable attrs value 表達；更新回傳新版本。
- `ApplicationRegistry` 只保存 immutable metadata 與 provider 宣告；`ContainerRuntime` 由 Adapter
  在 application boundary 建立，不要在執行期覆寫 runtime state。
- 單元測試放在 `tests/unit`，Adapter 契約測試放在 `tests/contract`，需要完整應用啟動的測試放在 `tests/integration`。
- pytest 將 warnings 視為 errors，讓未 await 的 coroutine 與相容性警告在開發階段即被發現。
