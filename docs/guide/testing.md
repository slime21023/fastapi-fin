# 測試與替換實作

`Application.with_overrides({Contract: fake})` 以公開契約替換物件，而不必改動路由、
providers 或既有 `Application`。鍵必須是已匯出的契約，值是準備好的實例，不是工廠。
替身以 `Scope.APP` 提供：HTTP 注入、其他模組的匯入，以及匯出模組內對該契約的依賴，
都取得同一個物件。若多次替換同一契約，以後一次為準。

每個測試可建立自己的替身與 `Application`，避免跨測試共享可變狀態。即使建立新容器，
容器也會使用你傳入的物件，不會複製它。

## 不啟動 FastAPI

下例沿用[快速入門](getting-started.md)存為 `app.py` 的範例。使用 `open_container()`
直接驗證依賴組裝與替換；若要讓測試完全不匯入 FastAPI，將模組宣告和服務型別放到
獨立的 Python 模組，再由 HTTP 入口與測試共同匯入。

```python
import asyncio

from app import InMemoryDirectory, UserDirectory, application

from fastapi_fin import open_container


def test_directory_override() -> None:
    fake = InMemoryDirectory({42: "測試使用者"})

    async def check() -> None:
        async with open_container(application.with_overrides({UserDirectory: fake})) as root:
            assert await root.get(UserDirectory) is fake

    asyncio.run(check())
```

若要測試 `Scope.REQUEST` 的服務，請先進入[子作用域](scopes.md)。

## 測試 HTTP 行為

把替換後的宣告傳給 app factory；用 `with TestClient(...)` 執行 lifespan，
讓請求收到容器所需的 ASGI state，並在測試結束時清理資源。

```python
from fastapi.testclient import TestClient

from app import InMemoryDirectory, UserDirectory, application, create_app


def test_get_user() -> None:
    fake = InMemoryDirectory({42: "測試使用者"})
    app = create_app(application.with_overrides({UserDirectory: fake}))

    with TestClient(app) as client:
        response = client.get("/users/42")

    assert response.status_code == 200
    assert response.json() == {"name": "測試使用者"}
```

## 本專案的測試分層

- Unit：不使用 FastAPI，驗證模組宣告、Dishka 依賴圖與資源清理。
- Contract：用 `TestClient` 與 lifespan 驗證原生路由、HTTP 注入與 OpenAPI 行為。
- Integration：執行[範例](../examples/index.md)，確認完整流程能在實際組裝後運作。
