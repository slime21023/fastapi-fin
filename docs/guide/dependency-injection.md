# Dependency Injection

FastAPI-Fin 使用明確的 provider dependency list，不根據 constructor annotation 自動
建立 provider graph。

## 建立 provider

如果 token 是 class 且沒有提供 factory，`provide()` 會使用該 class 建立 instance：

```python
from fastapi_fin.application import Scope, provide


class Database:
    pass


database_provider = provide(
    Database,
    scope=Scope.APPLICATION,
    eager=True,
)
```

需要傳入依賴時，列在 `dependencies`：

```python
class UserService:
    def __init__(self, database: Database) -> None:
        self.database = database


service_provider = provide(
    UserService,
    dependencies=(Database,),
    scope=Scope.REQUEST,
)
```

provider factory 可以是同步或非同步 callable，依賴會按照 declaration 給予 positional
arguments。

## 在 endpoint 使用 provider

用 `inject()` 將 provider token 放入 endpoint 的 default：

```python
from fastapi_fin.application import inject


def list_users(
    service: UserService = inject(UserService),
) -> list[str]:
    return ["example"]
```

Adapter 會將這個 marker 轉換成 FastAPI `Depends`，並保留原本的 endpoint signature。

## Scope

FastAPI-Fin 目前提供兩種 scope：

| Scope | Instance 數量 | 適合用途 |
| --- | --- | --- |
| `APPLICATION` | 每個 FastAPI app 一份 | connection pool、repository、設定服務 |
| `REQUEST` | 每個 request 一份 | request service、transaction、session |

`APPLICATION` provider 可以依賴另一個 application provider，但不能依賴 request
provider。request provider 可以依賴 application provider。

## eager 初始化

```python
provide(
    Database,
    scope=Scope.APPLICATION,
    eager=True,
)
```

`eager=True` 會在 app startup 時建立 provider。未設定 eager 的 application provider
會在第一次解析時建立，之後由 runtime 重複使用。

## Provider cleanup

使用 `disposer` 釋放資源：

```python
def close_database(database: Database) -> None:
    database.close()


provide(
    Database,
    scope=Scope.APPLICATION,
    eager=True,
    disposer=close_database,
)
```

disposer 可以是同步或非同步 callable。request scope 會在 request context 結束時反向
清理；application scope 會在 runtime shutdown 時反向清理。

## 重要限制

含有 `inject()` 的 endpoint 必須使用 `FastAPIAdapter.create_app()`。`mount()` 不會建立
runtime 或 request context，因此會拒絕 managed definition。
