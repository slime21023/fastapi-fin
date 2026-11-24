# Security 與 JWT

FastAPI-Fin 將 authentication 與 authorization 分開。JWT 只負責 token 的簽發與驗證，
scope、role 與 resource policy 則由獨立的 authorization policy 處理。

JWT 支援是 optional dependency：

```powershell
uv sync --locked --extra security
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

token = issuer.issue("user-1", scopes=("tasks:read",), roles=("admin",))
principal = verifier.authenticate(token)
```

依預設，`JwtVerifier` 會驗證簽章與演算法允許清單、`iss`、`aud`、時間宣告 `exp` 與 `iat`、身分欄位 `sub`、token ID `jti`，以及 header 的 `typ`（預設 `at+jwt`）。對稱式演算法的簽發與驗證使用相同密鑰；不要從 token header 決定允許的演算法，也不要把 JWT 當成加密資料。

若多個服務只需要驗證而不應持有簽發私鑰，可使用非對稱簽章：簽發端持有私鑰，驗證端持有受信任的公鑰。本地金鑰輪替可以使用不可變的 `JwtKeySet`：

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
若使用這個 RS256 verifier，簽發端也要使用 `RS256`，並以對應的私鑰和 `key_id` 建立 `JwtIssuer`；此 verifier 無法驗證上面以 HS256 簽發的 token。

## 將認證合約接到 FastAPI

`JwtVerifier` 已符合 `TokenAuthenticator` 合約。用 Dishka provider 提供該合約，並由模組匯出。`FastAPISecurity` 不直接接收 verifier，而是透過 `Inject[TokenAuthenticator]` 解析它。以下沿用上節選定的 `verifier`：

```python
from typing import Annotated

from dishka import Provider, Scope, provide
from fastapi import FastAPI

from fastapi_fin import Application, FastAPIIntegration, FastAPISecurity, Module
from fastapi_fin.security import AuthenticatedPrincipal, TokenAuthenticator, require_roles


class AuthProvider(Provider):
    @provide(scope=Scope.APP)
    def authenticator(self) -> TokenAuthenticator:
        return verifier


auth = Module(
    name="auth",
    providers=(AuthProvider(),),
    exports=(TokenAuthenticator,),
)
integration = FastAPIIntegration(Application(modules=(auth,)))
app = FastAPI(lifespan=integration.lifespan)
security = FastAPISecurity(
    token_url="/token",
    scopes={"tasks:read": "讀取工作"},
)


@app.get("/tasks")
async def list_tasks(
    principal: Annotated[
        AuthenticatedPrincipal,
        security.principal_marker(scopes=("tasks:read",)),
    ],
) -> dict[str, str]:
    return {"subject": principal.subject}


@app.get("/admin")
async def admin_area(
    principal: AuthenticatedPrincipal = security.require(require_roles("admin")),
) -> dict[str, str]:
    return {"subject": principal.subject}
```

`principal_marker()` 使用 FastAPI `Security` 依賴；有 `token_url` 時使用 OAuth2 password bearer scheme，並把宣告的 scopes 顯示在 OpenAPI 中。`token_url` 指向應用程式或身分服務實作的 token endpoint；adapter 不會建立該路由。省略 `token_url` 則使用 HTTP bearer scheme。

`security.require(policy)` 會先認證 bearer token，再檢查 `PrincipalPolicy`。範例中的 `/admin` 要求已驗證的 principal 具有 `admin` 角色，而 `/tasks` 要求 `tasks:read` scope。若需要資源層級授權，例如只能讀取自己建立的工作，應在應用程式查詢或服務中依據 principal 實作。

- 缺少或無效 token：`401`，附帶 `WWW-Authenticate: Bearer`。
- token 有效但 scope 不足：`403`，附帶 `WWW-Authenticate` 的 `insufficient_scope` 資訊。
- 通過 scope 檢查但角色不符：`403`。

可改由其他 provider 提供同步或非同步的 `TokenAuthenticator`。預期的憑證拒絕應拋出 `AuthenticationError`（例如 `InvalidTokenError`），而非吞掉服務錯誤。未匯出 `TokenAuthenticator` 時，只要啟動驗證在路由上找到該認證依賴，lifespan 就會拋出 `AssemblyError`。

## Token lifecycle 邊界

目前 JWT issuer/verifier 不負責：

- 使用者密碼儲存與登入資料庫
- refresh token rotation
- logout 或即時 token revocation
- 外部 OIDC provider discovery

這些應由 application provider 或外部 identity service 實作。Access token 建議短效；
需要即時撤銷時，應增加 revocation store 或採用 opaque refresh/session token，而不是
假設 JWT 可以自行 logout。

可執行範例請參考 [`06_security_jwt.py`](https://github.com/slime21023/fastapi-fin/blob/main/examples/06_security_jwt.py)；完整簽章、認證與授權 API 見[安全性參考](../reference/security.md)。
