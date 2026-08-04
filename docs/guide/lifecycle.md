# Lifecycle 與資源管理

## Lifecycle hooks

使用 `LifecycleDefinition` 宣告 startup 與 shutdown hooks：

```python
from fastapi_fin.application import ApplicationDefinition, LifecycleDefinition


def initialize_metrics() -> None:
    pass


async def close_metrics() -> None:
    pass


definition = ApplicationDefinition(
    lifecycle=LifecycleDefinition(
        startup=(initialize_metrics,),
        shutdown=(close_metrics,),
    ),
)
```

hook 可以是同步或非同步 callable，且不接收參數。

## 執行順序

使用 `create_app()` 時，生命週期順序如下：

```text
runtime.start()
    ↓
eager application providers
    ↓
startup hooks（宣告順序）
    ↓
custom lifespan startup
    ↓
處理 requests
    ↓
custom lifespan shutdown
    ↓
shutdown hooks（反向順序）
    ↓
runtime.stop()
```

如果 startup 失敗，已建立的 application provider 會嘗試清理。shutdown 時，即使其中
一個 hook 或 disposer 失敗，runtime 仍會繼續進行其餘 cleanup，最後以 exception group
回報錯誤。

## FastAPI lifespan 整合

可以傳入額外的 FastAPI lifespan context manager：

```python
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from fastapi import FastAPI

from fastapi_fin.adapters import FastAPIAdapter


@asynccontextmanager
async def external_lifespan(app: FastAPI) -> AsyncIterator[None]:
    print("external startup")
    yield
    print("external shutdown")


app = FastAPIAdapter.create_app(
    definition,
    lifespan=external_lifespan,
)
```

FastAPI-Fin 的 runtime 與 lifecycle hooks 仍由 Adapter 統一管理。
