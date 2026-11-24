# Security 與 JWT

Security API 分成三層：

1. `TokenAuthenticator`：描述從 bearer token 取得 principal 的合約；`JwtIssuer` / `JwtVerifier` 提供 JWT 簽發與驗證。
2. `AuthenticatedPrincipal` / `PrincipalPolicy`：保存身分與 claims，並描述 scope 與角色授權規則。
3. `FastAPISecurity`：透過 `Inject[TokenAuthenticator]` 將認證接到 FastAPI `Security`。

前兩層由 `fastapi_fin.security` 匯出；`FastAPISecurity` 由 `fastapi_fin.adapters` 匯出。這些公開名稱也可從 `fastapi_fin` 匯入。

JWT 支援使用 optional dependency：

```console
pip install "fastapi-fin[security]"
```

未安裝 `PyJWT` 時，首次使用 issuer 或 verifier 會 raise `SecurityDependencyError`。

## `TokenAuthenticator`

```python
class TokenAuthenticator(Protocol):
    def authenticate(
        self, token: str
    ) -> AuthenticatedPrincipal | Awaitable[AuthenticatedPrincipal]: ...
```

`token` 是不含 `Bearer` 前綴的憑證。同步 `JwtVerifier` 已符合此合約，不須繼承。客製實作也可以回傳 awaitable；預期的憑證拒絕應拋出 `AuthenticationError` 或其子類別。

## `AuthenticatedPrincipal`

```python
@define(frozen=True, slots=True)
class AuthenticatedPrincipal:
    subject: str
    issuer: str
    audience: tuple[str, ...]
    scopes: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    token_id: str | None = None
    token_type: str | None = None
    claims: Mapping[str, object] = {}
```

建構時會 trim 並驗證 identity text，將 scopes、roles 與 audience 正規化成 tuple，並
遞迴 freeze claims 中的 mapping/list/tuple。principal 建立後不能修改。

```python
principal.has_scope(scope: str) -> bool
principal.has_role(role: str) -> bool
```

`has_scope()` 與 `has_role()` 是 exact membership check，不會自行做 wildcard、hierarchy
或 role inheritance。若需要複合規則，請使用 `PrincipalPolicy` 或 application service。

## `JwtKeySet`

```python
@define(frozen=True, slots=True, kw_only=True)
class JwtKeySet:
    keys: Mapping[str, object]

    def __call__(self, header: Mapping[str, object]) -> object: ...
```

`JwtKeySet` 是 local trusted key resolver：

- key IDs 必須是非空字串。
- 金鑰映射必須非空，會複製成唯讀映射；金鑰 ID 去除前後空白後不得重複。
- 缺少、無效或未知的 `kid` 會拋出 `InvalidTokenError`。
- 不會依照 token header 的 URL、issuer 或其他值自動發出網路請求。

```python
key_set = JwtKeySet(
    keys={
        "previous": previous_public_key,
        "current": current_public_key,
    },
)
```

key rotation 的切換順序通常是：先將新 public key 加入 verifier，再由 issuer 使用新的
`key_id`，最後移除已過期 token 不再需要的舊 key。

`JwtKeyResolver = Callable[[Mapping[str, object]], object]`。自訂 resolver 收到的是尚未驗證的 JWT header；只能用它選擇已受信任的金鑰，不能把內容當作身分或信任依據。

## `JwtVerifier`

```python
@define(frozen=True, slots=True, kw_only=True)
class JwtVerifier:
    key: object | None = None
    key_resolver: JwtKeyResolver | None = None
    algorithms: tuple[str, ...]
    issuer: str
    audience: str | tuple[str, ...]
    required_claims: tuple[str, ...] = ("exp", "iat", "iss", "sub", "aud")
    expected_type: str | None = "at+jwt"
    require_jti: bool = True
    leeway: float = 0
    scope_claim: str = "scope"
    roles_claim: str = "roles"
```

建構時的必要條件：

- `key` 與 `key_resolver` 必須二選一，不能同時提供或同時省略。
- `algorithms` 必須是明確的非空 allowlist。
- algorithm `none` 永遠不被接受。
- `issuer`、`audience` 與 claim names 必須有效。
- `require_jti=True` 時，`jti` 會自動加入 required claims。

```python
def authenticate(self, token: str) -> AuthenticatedPrincipal: ...
```

驗證流程包括：

1. 讀取未驗證 header，只用於檢查 `alg`、`typ` 與選擇 trusted key。
2. 用設定的 algorithm allowlist 驗證 signature。
3. 依設定驗證 issuer、audience、時間與必備宣告。
4. 將 claims 正規化成不可變的 `AuthenticatedPrincipal`。`token_type` 取自設定的 `expected_type`；若設定為 `None`，則不檢查 header 的 `typ`，principal 的 `token_type` 也是 `None`。

不受信任的演算法、token 類型、簽章或 PyJWT 驗證失敗會以 `InvalidTokenError` 回報；principal 欄位無效也會拋出 `InvalidTokenError`。未能載入 PyJWT 則是 `SecurityDependencyError`，不是認證拒絕。

## `JwtIssuer`

```python
@define(frozen=True, slots=True, kw_only=True)
class JwtIssuer:
    key: object
    algorithm: str
    issuer: str
    audience: str | tuple[str, ...]
    lifetime: timedelta = timedelta(minutes=15)
    token_type: str = "at+jwt"
    key_id: str | None = None
    scope_claim: str = "scope"
    roles_claim: str = "roles"
```

```python
def issue(
    self,
    subject: str,
    *,
    scopes: Iterable[str] = (),
    roles: Iterable[str] = (),
    token_id: str | None = None,
    additional_claims: Mapping[str, object] | None = None,
    now: datetime | None = None,
) -> str: ...
```

issuer 自動產生：

- `iss`：issuer
- `sub`：subject
- `aud`：audience
- `iat`：issued time
- `exp`：`iat + lifetime`
- `jti`：指定的 token ID 或隨機 UUID
- header `typ`：`token_type`
- header `kid`：有設定 `key_id` 時加入

非空的 `scopes` 會以空白分隔字串寫入；非空的 `roles` 會以 list 寫入。`additional_claims` 不得覆寫 `iss`、`sub`、`aud`、`iat`、`exp`、`jti`、設定的 scope/role claim 名稱或 `kid`。

```python
issuer = JwtIssuer(
    key=private_key,
    algorithm="RS256",
    issuer="https://identity.example",
    audience="task-api",
    lifetime=timedelta(minutes=10),
    key_id="current",
)

token = issuer.issue(
    "user-1",
    scopes=("tasks:read",),
    roles=("operator",),
)
```

JWT 是 signed claims，不是 encrypted payload；不要將密碼、秘密或不應被 bearer token
持有者讀取的資料放進 claims。

## `PrincipalPolicy`

```python
@define(frozen=True, slots=True)
class PrincipalPolicy:
    scopes: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    all_roles: bool = True
    name: str = "principal-policy"
```

```python
policy.allows(principal: AuthenticatedPrincipal) -> bool
policy.enforce(principal: AuthenticatedPrincipal) -> None
```

- `name` 去除前後空白後必須非空，否則拋出 `DefinitionError`。
- `scopes` 必須全部具備。
- `all_roles=True` 時，`roles` 必須全部具備。
- `all_roles=False` 時，`roles` 只需任一個符合；空 roles 視為不增加限制。
- `allows()` 回傳 bool。
- `enforce()` 在 scope 缺少時拋出 `InsufficientScopeError`，其 `required_scopes` 在這裡只包含缺少的 scope；其他拒絕則拋出 `AuthorizationError`。

```python
def require_scopes(*scopes: str, name: str = "required-scopes") -> PrincipalPolicy: ...


def require_roles(
    *roles: str,
    all_roles: bool = True,
    name: str = "required-roles",
) -> PrincipalPolicy: ...
```

## `FastAPISecurity`

```python
FastAPISecurity(
    *,
    token_url: str | None = None,
    scopes: Mapping[str, str] | None = None,
    scheme_name: str | None = None,
    description: str | None = None,
)
```

`token_url` 有值時使用 FastAPI `OAuth2PasswordBearer`，並將 `scopes` 發布到 OpenAPI；沒有 `token_url` 時使用 `HTTPBearer`。兩者都使用 `auto_error=False`，由 adapter 處理認證及授權回應。Adapter 不會建立 token endpoint。

建構子不接收 authenticator。應用程式須以 Dishka provider 提供 `TokenAuthenticator`，在其 `Module` 宣告 `exports=(TokenAuthenticator,)`，再將該模組納入 `FastAPIIntegration` 的 `Application`。`token_url` 若非 `None`，必須是非空白文字；`scopes` 若提供，必須是非空白 scope 名稱到非空白描述的映射。設定不符時拋出 `AdapterError`。範例見[安全性指南](../guide/security.md)。

`scheme` 是選用的 FastAPI bearer scheme；`scopes` 是建構時複製的唯讀 scope 說明映射；`current_principal` 是解析 bearer 憑證、注入 authenticator 並檢查 FastAPI `SecurityScopes` 的依賴 callable。一般路由使用下列兩個 marker 方法。

### `principal_marker()`

```python
def principal_marker(
    self,
    *,
    scopes: tuple[str, ...] = (),
) -> SecurityMarker: ...
```

回傳可放在 `Annotated` metadata 的 FastAPI `Security` marker：

```python
@router.get("/tasks")
def list_tasks(
    principal: Annotated[
        AuthenticatedPrincipal,
        security.principal_marker(scopes=("tasks:read",)),
    ],
) -> list[TaskView]:
    return service.list_for(principal.subject)
```

要求的 scope 名稱必須是非空字串。若 `FastAPISecurity(scopes=...)` 提供非空映射，每個要求的 scope 都必須列在其中，否則建立 marker 時會拋出 `AdapterError`。空映射不執行名稱比對。

### `require()`

```python
def require(self, policy: PrincipalPolicy) -> DependsMarker: ...
```

回傳 FastAPI `Depends` marker。它透過 `Security` 以 policy 的 scopes 取得 principal，再執行 `policy.enforce()` 並回傳同一個 principal。傳入非 `PrincipalPolicy` 值或不符合設定的 scopes，會拋出 `AdapterError`：

```python
admin = require_roles("admin")


@router.get("/admin")
def admin_area(
    principal: Annotated[AuthenticatedPrincipal, security.require(admin)],
) -> dict[str, str]:
    return {"subject": principal.subject}
```

### HTTP 語義

| 情況 | Status | Header |
| --- | --- | --- |
| 缺少 bearer token、認證拒絕或回傳值不是 `AuthenticatedPrincipal` | `401` | `WWW-Authenticate: Bearer` |
| token 有效但 scope 不足 | `403` | `WWW-Authenticate: Bearer error="insufficient_scope", scope="..."` |
| token 有效但角色或 policy 拒絕 | `403` | 無特殊 bearer header |

HTTP scope 檢查所回傳的 `scope` 列出該依賴要求的 scopes，不只是缺少的項目。如果是 policy 自己拋出 `InsufficientScopeError`，adapter 使用例外內的 `required_scopes`。認證 adapter 不會把任意例外轉成 `401`；參見[錯誤](errors.md)。

## Token lifecycle 邊界

以下功能刻意不包含在 issuer/verifier：

- 帳號密碼儲存與登入資料庫。
- refresh token rotation。
- logout 與即時 revocation store。
- 外部 OIDC discovery 或 JWKS HTTP fetch。

這些功能應由應用程式、身分服務或外部 IdP 負責。應用程式負責為 verifier 設定已受信任的金鑰，或提供其他 `TokenAuthenticator` 實作。
