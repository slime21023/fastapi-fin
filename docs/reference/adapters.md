# FastAPI adapter

Adapter 是唯一可以依賴 FastAPI 的 layer。它把 framework-independent definitions、runtime
與 features 編譯成 FastAPI routes、dependencies、OpenAPI metadata 與 lifespan。

## `Lifespan`

```python
Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[object]]
```

可傳給 `FastAPIAdapter.create_app(lifespan=...)` 的 async context manager factory：

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI


@asynccontextmanager
async def external_lifespan(app: FastAPI):
    await connect_external_resources()
    try:
        yield
    finally:
        await disconnect_external_resources()
```

## `FastAPIAdapter.create_app()`

```python
@classmethod
def create_app(
    cls,
    definition: ApplicationDefinition,
    *,
    title: str = "FastAPI-Fin application",
    version: str = "1.0.1",
    description: str = "",
    lifespan: Lifespan | None = None,
) -> FastAPI: ...
```

`create_app()` 的責任：

1. 呼叫 `assemble(definition)`，在建立 FastAPI app 前驗證 definition。
2. 建立 application-specific `ApplicationRuntime`。
3. 將 startup/shutdown hooks 與 provider lifecycle 接到 FastAPI lifespan。
4. 將 routes 編譯成 FastAPI `APIRouter`。
5. 將 `Inject` marker 轉成 FastAPI `Depends`。
6. 將 Guard、Interceptor 與 request context 接到 endpoint execution pipeline。

```python
app = FastAPIAdapter.create_app(
    definition,
    title="Task API",
    version="2.4.0",
    description="Task management API",
    lifespan=external_lifespan,
)
```

### Lifespan 順序

正常啟動與關閉順序如下：

```text
ApplicationRuntime.start()
        ↓
LifecycleDefinition.startup（宣告順序）
        ↓
custom lifespan enter（若有）
        ↓
serve requests
        ↓
custom lifespan exit
        ↓
LifecycleDefinition.shutdown（反向順序）
        ↓
ApplicationRuntime.stop()
```

如果 eager provider 或 startup hook 失敗，應用程式不會進入 serving state，並會清理已建立
的 runtime resources。

### Request execution 順序

對包含 runtime 或 policy 的 endpoint，主要順序是：

```text
FastAPI parameter/body validation
        ↓
FastAPI Depends / provider resolution
        ↓
Guard evaluation
        ↓
Interceptor chain
        ↓
endpoint
        ↓
RequestContext cleanup
```

Adapter 會保留 endpoint 的公開 signature，讓 FastAPI 仍能辨識 path/query/body、Pydantic
model 與 response model。Guard 所需的 internal `Request` dependency 不會成為公開 API
參數。

## `FastAPIAdapter.mount()`

```python
@classmethod
def mount(
    cls,
    app: FastAPI,
    definition: ApplicationDefinition,
) -> FastAPI: ...
```

`mount()` 將 stateless routes 加入既有 FastAPI app，並回傳同一個 `FastAPI` instance。

適用條件：

- `definition.providers` 必須為空。
- `definition.lifecycle.startup` 與 `shutdown` 必須為空。
- route endpoint 不可使用 `inject()`。
- route-level 或 application-level Guard/Interceptor 可以使用，但它們不能依賴
  FastAPI-Fin runtime provider。

```python
from fastapi import FastAPI

app = FastAPI()
FastAPIAdapter.mount(app, stateless_definition)
```

若 definition 需要 provider、lifecycle 或 injection，`mount()` 會 raise `AdapterError`，
應改用 `create_app()`。

## Route metadata mapping

`RouteDefinition` 會映射到 FastAPI `APIRouter.add_api_route()`：

| FastAPI-Fin 欄位 | FastAPI 行為 |
| --- | --- |
| `methods` | HTTP method list |
| `name` | route name |
| `deprecated` | OpenAPI deprecated flag |
| `include_in_schema` | 是否輸出到 OpenAPI |
| `response_model` | response validation/schema |
| `status_code` | success status code |
| `tags` | OpenAPI tags |
| `summary`、`description` | operation metadata |
| `response_description` | response description |
| `operation_id` | operation ID |

FastAPI 本身仍負責 Pydantic validation、422 response、dependency graph 與 OpenAPI schema。

## HTTP error mapping

| Core error | Adapter response |
| --- | --- |
| `AccessDeniedError` from Guard | `403 forbidden` |
| `ResolutionError` during injection | `500 dependency resolution failed` |
| closed runtime | runtime/adapter failure，不應在正常 serving state 發生 |
| FastAPI validation failure | FastAPI 原生 `422` |

Authentication 與 authorization 的 bearer-specific mapping 由
[`FastAPISecurity`](security.md#fastapisecurity) 負責，不由一般 `FastAPIAdapter` 猜測。

## 直接使用 Adapter 的限制

`FastAPIAdapter` 只使用 FastAPI 公開 API。不要從 endpoint 或 application core 直接依賴
Adapter 內部的 wrapper、generated dependency 或 private Starlette object；需要自訂
行為時，應使用 `ApplicationDefinition`、`ApplicationRouter`、`FastAPISecurity` 或
FastAPI 官方 middleware/dependency extension point。
