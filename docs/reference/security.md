# Security 與 JWT

Security API 分成三層：

1. `JwtIssuer` / `JwtVerifier`：簽發與驗證 token。
2. `AuthenticatedPrincipal` / `PrincipalPolicy`：保存 identity、claims 與授權規則。
3. `FastAPISecurity`：將 framework-independent authentication 接到 FastAPI `Security`。

JWT 支援使用 optional dependency：

```powershell
uv add "fastapi-fin[security]"
```

未安裝 `PyJWT` 時，首次使用 issuer 或 verifier 會 raise `SecurityDependencyError`。

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
- keys 會被複製成 immutable mapping。
- header 必須包含 `kid`。
- 未知 `kid` 會 raise `InvalidTokenError`。
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
    leeway: int | float = 0
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
3. 驗證 issuer、audience、expiry、issued-at 與 required claims。
4. 將 claims 正規化成 immutable `AuthenticatedPrincipal`。

任何 token 結構、signature、時間、issuer、audience、type 或 claim 錯誤都會轉成
`InvalidTokenError`，不將底層 JWT library 的細節暴露給 HTTP client。

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

`scopes` 會以 OAuth scope space-delimited string 寫入 token；`roles` 會以 list 寫入。
`additional_claims` 不能覆寫 registered claims、scope/role claims 或 `kid`。

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

- `scopes` 必須全部具備。
- `all_roles=True` 時，`roles` 必須全部具備。
- `all_roles=False` 時，`roles` 只需任一個符合；空 roles 視為不增加限制。
- `allows()` 回傳 bool。
- `enforce()` 在 scope 缺少時 raise `InsufficientScopeError`，其他拒絕 raise
  `AuthorizationError`。

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
Authenticator = Callable[
    [str],
    AuthenticatedPrincipal | Awaitable[AuthenticatedPrincipal],
]
```

```python
FastAPISecurity(
    authenticator: Authenticator,
    *,
    token_url: str | None = None,
    scopes: Mapping[str, str] | None = None,
    scheme_name: str | None = None,
    description: str | None = None,
)
```

`token_url` 有值時使用 FastAPI `OAuth2PasswordBearer`，並將 `scopes` 發布到 OpenAPI；
沒有 `token_url` 時使用 `HTTPBearer`。兩者都使用 `auto_error=False`，由 adapter 統一
產生錯誤語義。

### `principal_marker()`

```python
def principal_marker(
    self,
    *,
    scopes: tuple[str, ...] = (),
) -> Any: ...
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

scope 必須先在 `FastAPISecurity(scopes=...)` 宣告，否則 registration 時會 raise
`AdapterError`。

### `require()`

```python
def require(self, policy: PrincipalPolicy) -> Any: ...
```

回傳帶有 authentication 與 policy enforcement 的 FastAPI `Depends` marker：

```python
admin = require_roles("admin")


@router.get("/admin")
def admin_area(
    principal: AuthenticatedPrincipal = security.require(admin),
) -> dict[str, str]:
    return {"subject": principal.subject}
```

### `guard()`

```python
def guard(self, policy: PrincipalPolicy) -> GuardDefinition: ...
```

將 policy 轉成既有 Guard。endpoint 必須同時放置 `principal_marker()` 或
`security.require(...)`，讓 FastAPI 在 Guard 執行前把 principal 放入 request state：

```python
@router.get("/admin", guards=(security.guard(admin),))
def guarded_admin(
    principal: Annotated[AuthenticatedPrincipal, security.principal_marker()],
) -> dict[str, str]:
    return {"subject": principal.subject}
```

### HTTP 語義

| 情況 | Status | Header |
| --- | --- | --- |
| 缺少或無效 bearer token | `401` | `WWW-Authenticate: Bearer` |
| token 有效但 scope 不足 | `403` | `insufficient_scope` |
| token 有效但 role/policy 拒絕 | `403` | 無特殊 bearer error |

## Token lifecycle 邊界

以下功能刻意不包含在 issuer/verifier：

- 帳號密碼儲存與登入資料庫。
- refresh token rotation。
- logout 與即時 revocation store。
- 外部 OIDC discovery 或 JWKS HTTP fetch。

這些功能應由 application provider、identity service 或外部 IdP 負責，再將 trusted key
或 authenticator 注入 FastAPI-Fin。
