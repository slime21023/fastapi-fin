# 安裝與第一個 App

FastAPI-Fin 0.9.1 需要 Python 3.12 以上，目前尚未發布。取得原始碼後，在專案根目錄安裝：

```console
uv sync --locked
```

## 定義服務契約並接上路由

下例以 `UserDirectory` 描述路由所需的能力，讓路由不必知道使用者資料存在哪裡。
Dishka 的 `@provide` 以回傳型別註冊契約，`Module.exports` 將契約公開給路由。
路由本身仍用原生 FastAPI 宣告。

將以下程式存成 `app.py`。`uv sync --locked` 已安裝範例使用的測試客戶端。

```python
from typing import Protocol

from dishka import Provider, Scope, provide
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fastapi_fin import Application, FastAPIIntegration, Inject, Module


class UserDirectory(Protocol):
    def find_name(self, user_id: int) -> str | None: ...


class InMemoryDirectory:
    def __init__(self, names: dict[int, str]) -> None:
        self._names = names

    def find_name(self, user_id: int) -> str | None:
        return self._names.get(user_id)


class UsersProvider(Provider):
    @provide(scope=Scope.APP)
    def directory(self) -> UserDirectory:
        return InMemoryDirectory({42: "小林"})


application = Application(
    modules=(
        Module(
            name="users",
            providers=(UsersProvider(),),
            exports=(UserDirectory,),
        ),
    ),
)


def create_app(application: Application) -> FastAPI:
    integration = FastAPIIntegration(application)
    app = FastAPI(lifespan=integration.lifespan)

    @app.get("/users/{user_id}")
    async def get_user(user_id: int, directory: Inject[UserDirectory]) -> dict[str, str]:
        name = directory.find_name(user_id)
        if name is None:
            raise HTTPException(status_code=404, detail="找不到使用者")
        return {"name": name}

    return app


app = create_app(application)

if __name__ == "__main__":
    with TestClient(app) as client:
        response = client.get("/users/42")
        assert response.status_code == 200
        assert response.json() == {"name": "小林"}
```

執行 `uv run python app.py` 驗證範例。`TestClient` 必須以 `with` 啟動，才能執行
lifespan 並將容器傳給 HTTP 請求。`user_id` 仍由 FastAPI 解析與驗證；
`directory` 是依賴，不是 HTTP 參數。

## 用 Uvicorn 啟動

把同一個 `app` 交給 Uvicorn：

```console
uv run --with uvicorn uvicorn app:app
```

`if __name__ == "__main__":` 區塊只在 `python app.py` 時執行，Uvicorn 不會執行它；容器由 lifespan 在伺服器啟動時建立，並在關閉時清理。細節見[使用 Uvicorn 啟動](deployment.md)。

接著可閱讀[模組與契約](modules.md)、[FastAPI 整合](fastapi.md)，或用
[契約替換來測試](testing.md)。
