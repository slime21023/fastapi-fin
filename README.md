# FastAPI-Fin

FastAPI-Fin 是以 `attrs` 為核心的 FastAPI 架構擴展，提供不可變 metadata、DI container、宣告式 Guard、Interceptor、typed events 與 typed configuration，同時保留 FastAPI 的 OpenAPI、Pydantic validation 與 ASGI middleware 生態。

## 快速開始

```python
from fastapi import FastAPI

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import MetadataRegistry, controller, get, module


@controller(prefix="/users")
class UserController:
    @get("/{user_id}")
    def get_user(self, user_id: int) -> dict[str, int]:
        return {"user_id": user_id}


@module(prefix="/api", controllers=(UserController,))
class ApiModule:
    pass


registry = MetadataRegistry().register_module(ApiModule)
app = FastAPI(title="My FastAPI app")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


FastAPIAdapter(app).include(registry)
```

FastAPI 仍然是 application 的主要入口；FastAPI-Fin 只透過 Adapter 將宣告式 routes
掛載到既有 app，不取代 FastAPI 的 route、middleware 或 OpenAPI 使用方式。若配置
`ContainerRuntime` 或 `EventDispatcher`，才使用 `create_app()`，讓 Adapter 能正確管理
application lifespan。

需要在框架無關的環境檢查組裝結果時，可使用 `compile_application()` 取得 immutable
`CompiledApplication`；FastAPI Adapter 內部也使用此 compiler，再將結果掛載為
`APIRouter`。

`FastAPIAdapter` 可從 `fastapi_fin.adapters` 匯入，也會由 root package lazy export。Controller 支援所有 `HttpMethod` convenience decorators，例如 `get`、`post`、`put`、`patch` 與 `delete`；多 method route 可使用 `route(..., methods=[...])`。
若需要讀取 decorator 產生的 immutable route metadata，可使用 root export 的
`get_route_metadata()`。

## DI 與 lifecycle

```python
from fastapi_fin import ContainerRuntime, ContainerSnapshot, Lifecycle

runtime = ContainerRuntime(
    snapshot=ContainerSnapshot().bind(
        UserController,
        UserController,
        lifecycle=Lifecycle.REQUEST,
    )
)
app = FastAPIAdapter.create_app(registry, container_runtime=runtime)
```

Container snapshot 是 immutable attrs value。`request` / `transient` service 的 `close()` 或 `aclose()` 會在 request 結束時釋放；singleton resource 會在 application shutdown 時釋放。singleton 不可依賴 request-scoped service。

Framework-independent code 可使用 `ResolutionContext` 的 `with`／`async with` 自動管理
request/transient resource cleanup。

Sync／async lazy singleton 的並發初始化都會由 runtime 去重，確保同一 factory 只執行一次，
也適用於同步 endpoint 所在的 thread pool。

DI factory 支援現代 Python 的 `Annotated[Service, ...]` annotation，使用第一個 type
或 string token 解析服務。

HTTP request-time DI resolution 失敗時，Adapter 會回傳不暴露 container 細節的 generic
500 response；framework-independent core 仍使用 `ResolutionError`。

Typed config 的 optional setting 支援 parser-aware `default`，缺少環境或 raw input 時
仍會經過原始 parser。

Route decorators 支援 `response_model`、`status_code`、`tags`、`summary`、
`description`、`response_description` 與 `operation_id`，並保留 FastAPI 的 OpenAPI
與 Pydantic response validation。

Interceptor timeout 僅適用於 async pipeline；套用至純同步 endpoint 時會在組裝階段
拒絕，避免 timeout 設定被靜默忽略。

同步 pipeline 若在執行期間回傳 coroutine，也會立即拒絕，避免未 await 的 coroutine
被當成正常 endpoint 結果。

Guard predicate 必須回傳 `bool`；非布林結果會 fail closed，不會被當作 truthy 授權。

敏感設定除了可透過 `redacted()` 取得遮罩值外，`ConfigSnapshot` 的 `repr()` 也會
自動遮罩，避免 debug 輸出意外洩漏 secret。

retry、timeout、cache TTL、priority 與 snapshot version 會在宣告時進行嚴格數值驗證，
不接受 `bool` 或非有限的 timeout／TTL。

編譯 endpoint 使用的 runtime cache 會同步保護 lookup、store 與 eviction，適合同步
endpoint 在 thread pool 中併發執行；cache policy 本身仍是 immutable attrs value。

Typed event 可使用 immutable `EventDescriptor` 集中定義事件型別與 normalization 規則；
normalizer 支援同步與非同步 callable，`publish_async()` 會等待非同步 normalizer。既有
直接以 event type 訂閱的 API 仍然相容。

## 架構原則

- `fastapi_fin.core` 與 `fastapi_fin.application` 不依賴 FastAPI、Starlette 或 Pydantic。
- 只有 `fastapi_fin.adapters` 呼叫 FastAPI 公開 API。
- Adapter 邊界依責任拆分為 `app.py`（組裝）、`router.py`（路由轉譯）、
  `dependencies.py`（DI 轉譯）、`lifespan.py`（生命週期轉譯）與 `errors.py`（邊界錯誤）。
- root package 只在實際存取 `FastAPIAdapter` 或 `container_dependency` 時載入 FastAPI。
- metadata、binding、policy、subscription 與 config 都以 immutable `attrs` snapshot 表達。
- Adapter contract tests 驗證 FastAPI routing、Depends、lifespan、OpenAPI 與版本相容性。
- Adapter 建構參數與 lifespan handler 會在 boundary 即時驗證，避免錯誤延後到 application startup。

完整使用方式請參閱 [docs/usage.md](docs/usage.md)，舊版 API 遷移請參閱
[docs/migration.md](docs/migration.md)。
版本變更請參閱 [CHANGELOG.md](CHANGELOG.md)。

可執行的最小範例位於 [examples/README.md](examples/README.md)，涵蓋路由、DI、Guard、
Interceptor 與 lifecycle。

## 開發

```powershell
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run bandit -q -r fastapi_fin
uv run pytest
uv build
```

專案使用 Python 3.12+、`uv`、Ruff、ty、pytest 與 pre-commit；FastAPI Adapter 的 CI 會
在 Python 3.12／3.13 驗證兩組相容的 FastAPI／Starlette 版本 stack。
測試會將 warnings 視為 errors，避免未 await 的 coroutine 或相容性退化被忽略。
貢獻與 agent skills 使用方式請參閱 [CONTRIBUTING.md](CONTRIBUTING.md)。
