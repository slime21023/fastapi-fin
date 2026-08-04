# Route 與 FastAPI

## 使用 ApplicationRouter

`ApplicationRouter` 提供接近 FastAPI `APIRouter` 的 decorator 語法，但不依賴 FastAPI。
它只在 application declaration 階段收集 routes。建立 `ApplicationDefinition` 時，會
自動取得 router 的 immutable route snapshot：

```python
from fastapi_fin.application import ApplicationDefinition, ApplicationRouter, inject

router = ApplicationRouter(
    prefix="/users",
    tags=("users",),
)


@router.get("/{user_id}")
def read_user(
    user_id: int,
    service: UserService = inject(UserService),
) -> UserView:
    return service.get(user_id)


definition = ApplicationDefinition(
    routes=router,
)
```

`ApplicationRouter` 支援 `get()`、`post()`、`put()`、`patch()`、`delete()`、`options()`、
`head()`、`trace()`、`connect()` 與 `api_route()`。decorator 會回傳原本的 endpoint，
不會包裝或改變 endpoint signature。

Router-level 的 `prefix`、`tags`、Guard 與 Interceptor 會合併到每一條 route。多個
router 可以用 `include_router()` 組合，也可以在 `ApplicationDefinition` 建構時直接傳入：

```python
definition = ApplicationDefinition(
    routes=(users_router, admin_router),
)
```

`ApplicationDefinition` 建構完成後只保存固定的 `RouteDefinition` tuple；之後再對
router 註冊 route，不會改變已建立的 definition。`router.snapshot()` 仍可作為低階
檢查或特殊組合用途，但一般 application assembly 不需要手動呼叫。

## 使用低階 route API

使用 `route()` 宣告 path、endpoint 與 HTTP method：

```python
from fastapi_fin.application import ApplicationDefinition, route


def read_item(item_id: int) -> dict[str, int]:
    return {"item_id": item_id}


definition = ApplicationDefinition(
    routes=(
        route(
            "/items/{item_id}",
            read_item,
            methods="GET",
            tags=("items",),
            summary="Read one item",
            operation_id="read_item",
        ),
    ),
)
```

預設 method 是 `GET`。`methods` 可以是單一字串、`HttpMethod` 或 iterable；path 會被
正規化為以 `/` 開頭。

## Request 與 response model

FastAPI 的 Pydantic model 可以直接放在 endpoint signature 與 `response_model`：

```python
from pydantic import BaseModel, Field

from fastapi_fin.application import ApplicationDefinition, route


class UserCreate(BaseModel):
    name: str = Field(min_length=1)


class UserView(BaseModel):
    id: int
    name: str


def create_user(payload: UserCreate) -> UserView:
    return UserView(id=1, name=payload.name)


definition = ApplicationDefinition(
    routes=(
        route(
            "/users",
            create_user,
            methods="POST",
            response_model=UserView,
            status_code=201,
            tags=("users",),
        ),
    ),
)
```

Pydantic validation、422 response 與 OpenAPI schema 仍由 FastAPI 產生。

## Route metadata

`route()` 支援的主要 metadata：

| 參數 | 用途 |
| --- | --- |
| `name` | FastAPI route name |
| `deprecated` | 標示 OpenAPI operation 已棄用 |
| `include_in_schema` | 是否加入 OpenAPI |
| `response_model` | response validation 與 schema |
| `status_code` | 成功 response status code |
| `tags` | OpenAPI tags |
| `summary` | operation summary |
| `description` | operation description |
| `response_description` | response 說明 |
| `operation_id` | 明確指定 operation ID |

`operation_id` 只能用在只有一個 HTTP method 的 route 上。

`route()` 仍然是建立單一 immutable `RouteDefinition` 的低階 API，適合動態或集中式
assembly；`ApplicationRouter` 則適合按照功能拆分 route module。

## Route 與 policy

route 可以附加 route-level Guard 與 Interceptor：

```python
route(
    "/admin",
    dashboard,
    guards=(admin_guard,),
    interceptors=(audit_interceptor,),
)
```

application-level policy 則放在 `ApplicationDefinition`，會套用到所有 routes。詳情請看
[Guard 與 Interceptor](policies.md)。
