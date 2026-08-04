# Guard 與 Interceptor

## Guard

Guard 是 framework-independent predicate。Adapter 預設會把 FastAPI `Request` 作為
subject 傳入：

```python
from fastapi_fin.features import GuardDefinition


def admin_only(subject: object) -> bool:
    return getattr(subject, "headers", {}).get("X-Role") == "admin"


admin_guard = GuardDefinition(admin_only, name="admin-only")
```

掛到 route：

```python
route(
    "/admin",
    dashboard,
    guards=(admin_guard,),
)
```

也可以放到 `ApplicationDefinition.guards`，套用到所有 routes。

Guard predicate 可以是同步或非同步 callable，但必須回傳真正的 `bool`。回傳 `False`
時，FastAPI Adapter 會回傳：

```json
{"detail": "forbidden"}
```

HTTP status 為 `403`。

多個 Guard 依 `priority` 由高到低執行。Guard 發生在 FastAPI request validation 與
provider resolution 之後、Interceptor 之前。

## Interceptor

Interceptor 是 middleware-like chain，不暗中包含 retry、timeout、cache 或 error
translation：

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

Interceptor 可以掛在 application 或 route 上：

```python
definition = ApplicationDefinition(
    routes=(route("/dashboard", dashboard),),
    interceptors=(audit_interceptor,),
)
```

priority 越低越外層。例如 priority `0` 的 interceptor 會包住 priority `10` 的
interceptor。Guard 拒絕 request 時，Interceptor chain 不會執行。
