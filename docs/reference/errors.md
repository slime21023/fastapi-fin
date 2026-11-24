# 錯誤

## 例外階層與匯入位置

```text
FastAPIFinError
├─ DefinitionError
├─ AssemblyError
├─ AdapterError
└─ SecurityError
   ├─ SecurityDependencyError
   ├─ AuthenticationError
   │  ├─ MissingCredentialsError
   │  └─ InvalidTokenError
   └─ AuthorizationError
      └─ InsufficientScopeError
```

`fastapi_fin.errors` 只匯出 `FastAPIFinError`、`DefinitionError`、`AssemblyError` 和 `AdapterError`；`SecurityError` 及其子類別由 `fastapi_fin.security` 匯出。以上名稱也可從 `fastapi_fin` 匯入。

## 宣告、組裝與整合

| 例外 | 發生時機與處理責任 |
| --- | --- |
| `DefinitionError` | `Module`、`Application` 的欄位格式不合法，例如空模組名稱、重複合約項目或 provider 自行設定 component；也用於 `build_container()` 的無效 context 宣告，以及 JWT、policy 的無效設定。修正輸入。 |
| `AssemblyError` | `Application` 偵測到重複模組名稱、重複匯出，或覆寫目標並未匯出；`build_container()` 偵測未滿足的 `requires`、context 與匯出衝突，或收到非 `Application` 的值。指定的 Dishka graph 例外會封裝為 `AssemblyError`，原始錯誤保留在 `__cause__`。FastAPI lifespan 也會在偵測到路由注入未匯出的合約時拋出此錯誤。修正組裝與依賴宣告。 |
| `AdapterError` | `Inject[T]` 收到字串、`None` 或不可雜湊的合約鍵、整合物件或 lifespan 參數型別不符、啟動時偵測到 WebSocket 使用 `Inject`、請求沒有可用的容器，或安全性 adapter 設定無效。修正整合方式；這不是預期的 HTTP 認證失敗。 |

容器解析與 provider factory 的執行例外不會由 FastAPI-Fin 另行封裝，也不會被轉成固定格式的 `500` 回應。直接操作容器時由呼叫端處理；在 HTTP 請求中則遵循 FastAPI 的例外處理機制。容器與 scope 的清理錯誤由 Dishka 回報。

## 安全性例外

| 例外 | 意義 |
| --- | --- |
| `SecurityDependencyError` | 使用 JWT 時無法載入 PyJWT；從原始碼目錄執行 `uv sync --extra security`。這是部署問題，不是無效 token。 |
| `AuthenticationError` | 憑證無法通過認證。客製 `TokenAuthenticator` 可用此例外表示預期的認證失敗。 |
| `MissingCredentialsError` | 表示沒有提供憑證，供不依賴 FastAPI 的認證程式使用。 |
| `InvalidTokenError` | 表示 token 格式、簽章或信任條件不符，或 principal 欄位無效。 |
| `AuthorizationError` | 已認證的 principal 不符合授權政策。 |
| `InsufficientScopeError` | 授權所需 scope 不足；`required_scopes` 是建立例外時傳入的 scope tuple。`PrincipalPolicy.enforce()` 傳入缺少的項目。 |

`FastAPISecurity` 將缺少 bearer 憑證、`authenticate()` 拋出的 `AuthenticationError`，或 authenticator 未回傳 `AuthenticatedPrincipal` 的情況轉成 `401`。Adapter 偵測到 scope 不足，或 `require()` 執行 policy 拋出 `InsufficientScopeError` 時，會傳回含 `insufficient_scope` 的 `403`；其他由 policy 拋出的 `AuthorizationError` 轉成 `403`。這些映射只發生在該 adapter 的認證與授權流程，不是全域例外攔截器。詳見[安全性參考](security.md)。
