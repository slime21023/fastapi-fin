# 使用 Uvicorn 啟動

FastAPI-Fin 只需要 ASGI lifespan，所以用 Uvicorn 啟動與一般 FastAPI app 相同；不需要額外的設定、middleware 或啟動腳本。

## 啟動

將[快速入門](getting-started.md)的 app 存成 `main.py`，並確定 `app = FastAPI(lifespan=FastAPIIntegration(...).lifespan)` 位於模組層級：

```console
uv run --with uvicorn uvicorn main:app
```

多個 worker 同樣可用：

```console
uv run --with uvicorn uvicorn main:app --workers 2
```

以上指令、以程式啟動的 `uvicorn.Server`，以及 `--workers 2` 都實際驗證過：服務能回應請求，並在 Uvicorn 的 lifespan 啟動階段建立容器。

## 啟動與關閉時發生什麼事

- **啟動**：Uvicorn 進入 lifespan 時，整合會建立新的容器，並掃描路由中的 `Inject`。若路由注入了未匯出的契約，會拋出 `AssemblyError`，Uvicorn 印出 `Application startup failed. Exiting.` 並以非零狀態結束，不會開始接受請求。
- **關閉**：Uvicorn 收到 `SIGINT`／`SIGTERM` 或自行要求結束時，會關閉 lifespan，容器隨之關閉，`Scope.APP` 的 generator 工廠會執行清理。強制終止行程（例如 `kill -9`、Windows 的 `TerminateProcess`）不會執行清理。
- **每個請求**：`Inject` 為該請求進入 `Scope.REQUEST` 子容器，請求結束時清理該 scope 的資源。

## 多個 worker

每個 worker 是獨立的行程，各自執行 lifespan、各自建立容器。因此 `Scope.APP` 的實例是「每個 worker 一份」，不是全域單例：連線池會依 worker 數量倍增，記憶體內的快取或計數器不會在 worker 之間共用。需要跨 worker 共用的狀態應放在外部服務，例如資料庫或快取伺服器。

## 在啟動時建立 APP 資源

`Scope.APP` 的工廠在第一次被解析時才會執行，不會在 lifespan 啟動時自動執行。需要在開始接受請求前確認資料庫能連線時，在自己的 lifespan 中預先解析已匯出的契約；根容器放在整合交出的 state 的 `CONTAINER_STATE_KEY` 鍵：

```python
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from fastapi_fin import CONTAINER_STATE_KEY, FastAPIIntegration

integration = FastAPIIntegration(application)  # 你的 Application，且已匯出 Database


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[dict[str, object]]:
    async with integration.lifespan(app) as state:
        await state[CONTAINER_STATE_KEY].get(Database)  # 失敗時，Uvicorn 不會開始服務
        yield state


app = FastAPI(lifespan=lifespan)
```

預先解析只適用 `Scope.APP` 的匯出契約；`Scope.REQUEST` 的服務必須在請求的子容器內解析。

## 驗證範圍

- FastAPI 0.115.11 與 0.141.1，搭配 Uvicorn 0.54.0。
- FastAPI 0.141.1，搭配 Uvicorn 0.24.0、0.27.1、0.28.1、0.29.0 與 0.54.0（以程式啟動的 `uvicorn.Server` 驗證）。
- 在 Windows、Python 3.12 上驗證；未驗證 `--reload`、其他 ASGI 伺服器（如 Hypercorn）與 Gunicorn 的 Uvicorn worker。
