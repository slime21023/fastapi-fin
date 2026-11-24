# FastAPI-Fin

FastAPI-Fin 2.0 是 FastAPI 的 contract-first 依賴注入擴充。先定義服務介面，再由 Dishka provider 綁定實作；FastAPI 繼續負責路由、Pydantic 驗證與 OpenAPI。

- **模組契約**：以 `Module.exports` 公開契約、以 `Module.requires` 宣告跨模組依賴；組裝時驗證依賴圖。
- **原生 FastAPI**：以 `Inject[T]` 和 lifespan 整合。不需 middleware、專用 route class 或 endpoint decorator。
- **可隔離測試**：以 `Application.with_overrides()` 在新容器替換契約；worker 與測試可直接使用 `open_container()`。
- **直接使用 Dishka**：以原生 `Provider`、`provide`、`Scope` 宣告建構、作用域和清理。

## 快速開始

`pip install fastapi-fin`。以下可存為 `main.py`，再以 `uvicorn main:app` 啟動（需另裝 Uvicorn）。

```python
from typing import Protocol

from dishka import Provider, Scope, provide
from fastapi import FastAPI

from fastapi_fin import Application, FastAPIIntegration, Inject, Module


class Message(Protocol):
    def text(self) -> str: ...


class Hello:
    def text(self) -> str:
        return "hello"


class Messages(Provider):
    message = provide(Hello, provides=Message, scope=Scope.APP)


services = Application((Module("messages", providers=(Messages(),), exports=(Message,)),))
app = FastAPI(lifespan=FastAPIIntegration(services).lifespan)


@app.get("/")
def hello(message: Inject[Message]) -> dict[str, str]:
    return {"message": message.text()}
```

## 組裝邊界

```mermaid
flowchart LR
    Module["Module：exports / requires"] --> Application["Application"]
    Application --> Build["build_container：Dishka"]
    Build --> Adapter["FastAPIIntegration：lifespan / Inject"]
    Build --> Worker["Worker / script"]
```

2.0 與 1.x 不相容。以原生 FastAPI router 與 lifespan 取代舊 Application/Adapter；以 Dishka 取代原 DI runtime。JWT 與 principal policy 保留，認證實作以 `TokenAuthenticator` 契約組裝。Guard、Interceptor、Events、Config、Cache 已移除。

[使用文件](docs/index.md) · [可執行範例](examples/README.md) · [開發指南](CONTRIBUTING.md)

