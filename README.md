# FastAPI-Fin

FastAPI-Fin 1.0.0 是一個以 FastAPI 為宿主的應用程式組裝擴展。它提供明確的 route
definition、provider lifecycle、request context、Guard 與 Interceptor，同時保留
FastAPI 的路由、OpenAPI、Pydantic validation 與 ASGI lifespan 行為。

1.0.0 採 clean-slate 設計，不提供舊版 API 相容層。

## 快速開始

```python
from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationDefinition, route


def get_user(user_id: int) -> dict[str, int]:
    return {"user_id": user_id}


definition = ApplicationDefinition(
    routes=(route("/users/{user_id}", get_user),),
)
app = FastAPIAdapter.create_app(definition, title="My application")
```

如果只需要把無 runtime 狀態的 routes 掛載到既有 FastAPI app：

```python
from fastapi import FastAPI

app = FastAPI()
FastAPIAdapter.mount(app, definition)
```

包含 providers 或 lifecycle hooks 的 definition 必須使用 `create_app()`，由 Adapter
統一管理 startup、request context 與 shutdown。

## DI

Provider 使用明確 dependency list，不依賴 runtime annotation graph 推導：

```python
from fastapi_fin.application import Scope, inject, provide


class Database:
    pass


class UserService:
    def __init__(self, database: Database) -> None:
        self.database = database


definition = ApplicationDefinition(
    routes=(route("/users", list_users),),
    providers=(
        provide(Database, scope=Scope.APPLICATION, eager=True),
        provide(UserService, dependencies=(Database,)),
    ),
)
```

Endpoint 參數可用 `inject()` 取得 provider：

```python
def list_users(service: UserService = inject(UserService)) -> list[str]:
    return ["example"]
```

1.0.0 只有 `APPLICATION` 與 `REQUEST` 兩種 scope。Application model 會在啟動前驗證
missing provider、circular dependency 與 scope violation。

## 架構

```text
ApplicationDefinition
        │
        ▼
ApplicationModel（immutable、內部模型）
        │
        ├── ApplicationRuntime
        └── FastAPIAdapter
```

- `fastapi_fin.application`：definition、assembly 與 immutable model，不依賴 FastAPI。
- `fastapi_fin.runtime`：application runtime、provider resolver、request context。
- `fastapi_fin.features`：Guard、Interceptor、Events、Config 與 Cache 等獨立功能。
- `fastapi_fin.adapters`：唯一接觸 FastAPI 的 boundary。

Definition 是宣告；Model 是驗證後的結構；Runtime 是可變的執行狀態。Adapter 不會在
request time 重新編譯 route 或 provider graph。

## 開發

```powershell
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest
uv run bandit -q -r fastapi_fin
uv build
```

範例位於 [examples/README.md](examples/README.md)，使用方式說明位於
[docs/usage.md](docs/usage.md)，完整範例導讀位於 [docs/examples.md](docs/examples.md)。
