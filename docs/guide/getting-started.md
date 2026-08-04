# 安裝與第一個 App

## 安裝

FastAPI-Fin 支援 Python 3.12 以上。使用 `uv` 時，可以在專案中執行：

```powershell
uv add fastapi-fin
```

若要從原始碼閱讀或執行範例：

```powershell
uv sync --locked
```

## 建立 managed application

`create_app()` 會建立 FastAPI app，並由 Adapter 管理 runtime 的 startup、request
context 與 shutdown：

```python
from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationDefinition, route


def get_user(user_id: int) -> dict[str, int]:
    return {"user_id": user_id}


definition = ApplicationDefinition(
    routes=(route("/users/{user_id}", get_user),),
)
app = FastAPIAdapter.create_app(
    definition,
    title="User API",
    version="1.0.1",
)
```

endpoint 仍然是一般 FastAPI callable。path、query、body 與 response validation 都由
FastAPI 處理。

## 掛載到既有 FastAPI app

沒有 provider、`inject()` 或 lifecycle hook 時，可以使用 `mount()`：

```python
from fastapi import FastAPI

from fastapi_fin.adapters import FastAPIAdapter


app = FastAPI(title="Existing application")
FastAPIAdapter.mount(app, definition)
```

`mount()` 只掛載 stateless routes。需要 runtime 管理的 definition 必須使用
`create_app()`。

## 兩個入口的選擇

| 情境 | 使用方式 |
| --- | --- |
| FastAPI-Fin 管理 provider 與 lifecycle | `FastAPIAdapter.create_app()` |
| endpoint 使用 `inject()` | `FastAPIAdapter.create_app()` |
| 只有無狀態 routes | `FastAPIAdapter.mount()` |
| 已有 FastAPI app，需要加入 routes | `FastAPIAdapter.mount()` |

## 本地測試

使用 `TestClient` 時，建議以 context manager 包住 app，確保 lifespan 與 cleanup 被執行：

```python
from fastapi.testclient import TestClient


with TestClient(app) as client:
    response = client.get("/users/42")

assert response.status_code == 200
```

下一步可以閱讀[核心概念](concepts.md)，理解 definition、assembly、runtime 與 adapter
之間的關係。
