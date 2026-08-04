# FastAPI-Fin

FastAPI-Fin 是一個以 FastAPI 為宿主的應用程式組裝擴展。它以明確的 application
definition 組合 route、provider、request context、Guard、Interceptor 與 lifecycle，
同時保留 FastAPI 的路由、OpenAPI、Pydantic validation 與 ASGI lifespan 行為。

## 先看這裡

如果你第一次使用 FastAPI-Fin，建議依序閱讀：

1. [安裝與第一個 App](guide/getting-started.md)
2. [核心概念](guide/concepts.md)
3. [Dependency Injection](guide/dependency-injection.md)
4. [Lifecycle 與資源管理](guide/lifecycle.md)
5. [完整範例](examples/index.md)

## 最小範例

```python
from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationDefinition, route


def health() -> dict[str, str]:
    return {"status": "ok"}


definition = ApplicationDefinition(
    routes=(route("/health", health),),
)
app = FastAPIAdapter.create_app(definition, title="My application")
```

## 核心流程

```text
建立 ApplicationDefinition
        ↓
assemble() 驗證與組裝
        ↓
FastAPIAdapter 建立 FastAPI app
        ↓
ApplicationRuntime 管理 application/request state
        ↓
FastAPI 處理 request、validation 與 OpenAPI
```

## 需要選擇 Adapter 入口時

- 使用 `create_app()`：definition 含 provider、`inject()` 或 lifecycle hooks。
- 使用 `mount()`：只需要將無 runtime 狀態的 routes 掛到既有 FastAPI app。

完整使用方式請從[開始使用](guide/getting-started.md)開始。
