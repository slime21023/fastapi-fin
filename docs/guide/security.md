# Security 與 JWT

FastAPI-Fin 將 authentication 與 authorization 分開。JWT 只負責 token 的簽發與驗證，
scope、role 與 resource policy 則由獨立的 authorization policy 處理。

JWT 支援是 optional dependency：

```powershell
uv add "fastapi-fin[security]"
```

## 建立 JWT issuer 與 verifier

```python
from datetime import timedelta

from fastapi_fin.security import JwtIssuer, JwtVerifier

issuer = JwtIssuer(
    key=secret_key,
    algorithm="HS256",
    issuer="https://issuer.example",
    audience="task-api",
    lifetime=timedelta(minutes=15),
)

verifier = JwtVerifier(
    key=secret_key,
    algorithms=("HS256",),
    issuer="https://issuer.example",
    audience="task-api",
)
```

`JwtVerifier` 會明確驗證：

- signature algorithm allowlist
- `iss`、`aud`
- `exp`、`iat`、`sub`、`jti`
- JWT `typ`
- signature key

不要依賴 token header 自己宣告的 algorithm，也不要把 JWT 當成加密資料。多服務部署
建議使用非對稱簽章與 JWKS；本地 key rotation 可以使用 immutable `JwtKeySet`：

```python
from fastapi_fin.security import JwtKeySet, JwtVerifier

keys = JwtKeySet(
    keys={
        "old": old_public_key,
        "current": current_public_key,
    }
)

verifier = JwtVerifier(
    key_resolver=keys,
    algorithms=("RS256",),
    issuer="https://issuer.example",
    audience="task-api",
)
```

`kid` 只會在已設定的 trusted key set 中查找，不會依照 token 內的 URL 自動抓取外部
資源。

## FastAPI bearer 與 scopes

`FastAPISecurity` 將 framework-independent verifier 接到 FastAPI `Security` dependency，
同時保留 OpenAPI security scheme：

```python
from typing import Annotated

from fastapi_fin.adapters import FastAPISecurity
from fastapi_fin.security import AuthenticatedPrincipal

security = FastAPISecurity(
    verifier.authenticate,
    token_url="/token",
    scopes={"tasks:read": "Read tasks"},
)


@router.get("/")
def list_tasks(
    principal: Annotated[
        AuthenticatedPrincipal,
        security.principal_marker(scopes=("tasks:read",)),
    ],
) -> list[TaskView]:
    return service.list_for(principal.subject)
```

錯誤語義為：

- 缺少或無效 token：`401`，附帶 `WWW-Authenticate: Bearer`
- token 有效但 scope 不足：`403`，附帶 `insufficient_scope`
- token 有效但 role 或 policy 不允許：`403`

## Role policy 與 Guard

若 authorization policy 要以 FastAPI-Fin Guard 執行，可以讓 security adapter 將已驗證
的 principal 暫存於 request state：

```python
from fastapi_fin.security import require_roles

admin_policy = require_roles("admin")


@router.get(
    "/admin",
    guards=(security.guard(admin_policy),),
)
def admin_area(
    principal: Annotated[AuthenticatedPrincipal, security.principal_marker()],
) -> dict[str, str]:
    return {"subject": principal.subject}
```

endpoint 必須包含 `principal_marker()` 或 `security.require(...)`，確保 FastAPI 先完成
authentication，再由 Guard 執行 authorization。

也可以直接將 policy 做成 endpoint dependency：

```python
@router.get("/admin")
def admin_area(
    principal: AuthenticatedPrincipal = security.require(admin_policy),
) -> dict[str, str]:
    return {"subject": principal.subject}
```

## Token lifecycle 邊界

目前 JWT issuer/verifier 不負責：

- 使用者密碼儲存與登入資料庫
- refresh token rotation
- logout 或即時 token revocation
- 外部 OIDC provider discovery

這些應由 application provider 或外部 identity service 實作。Access token 建議短效；
需要即時撤銷時，應增加 revocation store 或採用 opaque refresh/session token，而不是
假設 JWT 可以自行 logout。

可執行範例請參考 [11_security_jwt.py](../../examples/11_security_jwt.py)。
