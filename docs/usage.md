# FastAPI-Fin 1.0.0 使用方式

## ApplicationDefinition

1.0.0 使用明確的 immutable definition 組裝應用程式。Route 不透過 controller/module
metadata 間接產生：

```python
from fastapi_fin.application import ApplicationDefinition, route


def health() -> dict[str, str]:
    return {"status": "ok"}


definition = ApplicationDefinition(
    routes=(route("/health", health, tags=("system",)),),
)
```

`route()` 會在建立時驗證 path、HTTP method、status code、OpenAPI metadata 與 policies。
重複的 method/path 組合會在 `assemble()` 或 `FastAPIAdapter.create_app()` 時拒絕。

## FastAPI Adapter

完整 application 使用 `create_app()`：

```python
from fastapi_fin.adapters import FastAPIAdapter

app = FastAPIAdapter.create_app(definition, title="Example", version="1.0.0")
```

只包含 stateless routes 的 definition 可以掛載到既有 app：

```python
from fastapi import FastAPI

app = FastAPI()
FastAPIAdapter.mount(app, definition)
```

若 definition 含 provider 或 lifecycle hook，`mount()` 會立即拋出 `AdapterError`，避免
runtime 沒有被 application lifespan 管理。

## Provider 與 Request Context

Provider 以明確 dependencies 建立 graph：

```python
from fastapi_fin.application import Scope, inject, provide


class Database:
    pass


class UserService:
    def __init__(self, database: Database) -> None:
        self.database = database


def users(service: UserService = inject(UserService)) -> list[str]:
    return ["user"]


definition = ApplicationDefinition(
    routes=(route("/users", users),),
    providers=(
        provide(Database, scope=Scope.APPLICATION, eager=True),
        provide(UserService, dependencies=(Database,), scope=Scope.REQUEST),
    ),
)
```

`APPLICATION` provider 每個 FastAPI app 只有一個 instance；`REQUEST` provider 在每個
request context 中只建立一次。Request 結束時會依建立順序反向執行明確的 `disposer`。

Runtime 只提供 async resolution path。Provider factory 可以是同步或非同步 callable，
Adapter 會在 request dependency 中統一等待結果。

## Guard

Guard 是 framework-independent predicate，Adapter 預設將 FastAPI `Request` 作為 subject：

```python
from fastapi_fin.features import GuardDefinition


def is_admin(request: object) -> bool:
    return request.headers.get("X-Role") == "admin"


admin_guard = GuardDefinition(is_admin, name="admin-only")
definition = ApplicationDefinition(
    routes=(route("/admin", dashboard, guards=(admin_guard,)),),
)
```

Predicate 必須回傳真正的 `bool`；false 會轉成 HTTP 403，其他型別會被視為 definition
錯誤。

## Interceptor

Interceptor 只有 middleware chain 語義：

```python
from collections.abc import Awaitable, Callable

from fastapi_fin.features import InterceptorDefinition


async def audit(
    next_call: Callable[[tuple[object, ...], dict[str, object]], Awaitable[object]],
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> object:
    print("request")
    return await next_call(args, kwargs)


audit_interceptor = InterceptorDefinition(audit, name="audit")
```

Retry、timeout、cache 與 error translation 不隱藏在 interceptor 中，應以獨立 feature
組合，避免 endpoint pipeline 產生不透明的執行語義。

## Lifecycle

Lifecycle hook 與 domain event bus 分離：

```python
from fastapi_fin.application import LifecycleDefinition


definition = ApplicationDefinition(
    lifecycle=LifecycleDefinition(
        startup=(initialize_metrics,),
        shutdown=(close_metrics,),
    ),
)
```

Startup hook 依序執行，shutdown hook 反向執行；runtime cleanup 在 shutdown hook 後執行。

## 測試分層

- `tests/unit`：Definition、assembly、runtime 與 optional features，不啟動 FastAPI。
- `tests/contract`：FastAPI route、OpenAPI、Depends、HTTP error 與 lifespan boundary。
- `tests/integration`：完整 definition 到 HTTP request 的流程。

## 延伸範例

由入門到完整 application 的範例學習路徑，請參考
[範例導讀](examples.md) 與 [examples/README.md](../examples/README.md)。
