# FastAPI 整合

使用原生 `FastAPI`、`APIRouter` 和 `Depends`，並把 `FastAPIIntegration(application).lifespan` 傳給 `FastAPI(lifespan=...)`。在 HTTP endpoint 或巢狀依賴的參數上寫 `service: Inject[Service]`，其中 `Service` 必須是已匯出的契約。`Inject[T]` 是附有 `Depends` 的 `Annotated`，不會將服務變成 OpenAPI 的參數或 request body。整合不加入 middleware、不替換路由類別，也不包裝 endpoint。

## 組合自己的 lifespan

若 app 已有 lifespan，請進入整合提供的 context manager，並將它交出的 state 與自己的資料合併後再 `yield`。以下程式可存成 `custom_app.py`，與[快速入門](getting-started.md)的 `app.py` 放在同一個目錄。

```python
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from app import UserDirectory, application
from fastapi_fin import FastAPIIntegration, Inject

integration = FastAPIIntegration(application)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[dict[str, object]]:
    async with integration.lifespan(app) as state:
        yield {**state, "service_name": "users-api"}


app = FastAPI(lifespan=lifespan)


@app.get("/users/{user_id}")
async def user_info(
    user_id: int, request: Request, directory: Inject[UserDirectory]
) -> dict[str, str | None]:
    return {
        "service": request.state.service_name,
        "name": directory.find_name(user_id),
    }
```

保留整合回傳的 state 鍵，不要用自己的值覆蓋。容器透過 ASGI lifespan state 傳給 `request.state`，不存放在 `app.state`。測試時應使用 `with TestClient(app)`；只建立 client 而不進入 context 不會啟動 lifespan。

## 請求、驗證與限制

- 同一 HTTP 請求內的 `Inject` 共用 Dishka `Scope.REQUEST` 容器。若模組需讀取當前請求，可在 `requires` 宣告 `fastapi.Request`，由 REQUEST scope 的 provider 透過一般 `request: Request` 參數取得。endpoint 若只需要請求物件，直接用原生 `Request` 參數，不用 `Inject[Request]`。
- 啟動時，整合會檢查已註冊的 FastAPI HTTP 路由及可辨識的巢狀依賴（含 router 的 `dependencies`）；注入未匯出的契約會拋出 `AssemblyError`。服務工廠在解析時拋出的例外不會被包裝，可由原生 FastAPI 例外處理機制處理。
- 掛載（`mount`）的子應用程式不在父應用程式的啟動掃描範圍內。若父應用程式已透過 lifespan 提供 state，掛載子應用程式的 HTTP 請求仍可使用該容器；這不等於父應用程式已驗證子應用程式的注入。
- `Inject` 僅支援 HTTP，不支援 WebSocket；若啟動掃描在 WebSocket 路由發現 `Inject`，會拋出 `AdapterError`。非 HTTP 程式應使用 [`open_container()`](scopes.md) 直接取得服務。
