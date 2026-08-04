# Errors

FastAPI-Fin 使用 typed exception hierarchy 區分「宣告錯誤」、「組裝錯誤」、「執行錯誤」
與「HTTP boundary mapping」。application code 應依責任層處理錯誤，不應用一個廣泛的
`except Exception` 把所有錯誤轉成相同 response。

## Hierarchy

```text
FastAPIFinError
├─ DefinitionError
├─ AssemblyError
├─ ResolutionError
│  └─ RuntimeClosedError
├─ AccessDeniedError
├─ AdapterError
└─ SecurityError
   ├─ SecurityDependencyError
   ├─ AuthenticationError
   │  ├─ MissingCredentialsError
   │  └─ InvalidTokenError
   └─ AuthorizationError
      └─ InsufficientScopeError
```

所有 public error 都可以從 `fastapi_fin.errors` 取得；Security errors 也會從
`fastapi_fin.security` re-export。

## Definition 與 assembly errors

### `DefinitionError`

代表單一 public input 或 immutable definition 欄位無效，應在 declaration time 修正：

- route path、HTTP method、status code 或 metadata 無效。
- provider token、scope、lifecycle hook 或 feature handler 無效。
- required configuration 缺少、parser 失敗或設定名稱未知。
- JWT issuer、algorithm、audience 或 key set 設定無效。

```python
from fastapi_fin.errors import DefinitionError

try:
    router = ApplicationRouter(prefix="not valid path")
except DefinitionError:
    ...
```

### `AssemblyError`

代表單一 definition 都可能有效，但組合後無法形成可執行 application：

- method/path route conflict。
- duplicate provider token。
- provider dependency 不存在。
- circular dependency。
- application provider 依賴 request provider。
- endpoint injection 找不到 provider。

`assemble()`、`FastAPIAdapter.create_app()` 與 `FastAPIAdapter.mount()` 都可能在 startup
前 raise `AssemblyError`。

## Runtime errors

### `ResolutionError`

代表 provider resolution 或 factory execution 失敗。Adapter 預設將 request-time
injection resolution failure 映射成 generic `500 dependency resolution failed`，避免將
內部錯誤細節傳給 client。

### `RuntimeClosedError`

代表 runtime 或 request context 已經關閉，或尚未啟動：

- 在 `ApplicationRuntime.start()` 前呼叫 `resolve()`。
- 在 `ApplicationRuntime.stop()` 後建立 request context。
- 在 `RequestContext.close()` 後追蹤或解析 request provider。

### Cleanup `ExceptionGroup`

`ApplicationRuntime.stop()` 與 `RequestContext.close()` 會嘗試執行全部 disposers。若多個
disposer 失敗，錯誤會合併成 `ExceptionGroup`，而不是在第一個失敗時停止 cleanup。

## Authorization errors

### `AccessDeniedError`

framework-independent Guard predicate 回傳 `False` 時 raise。FastAPI adapter 將它映射為
`403 forbidden`。

### `AuthorizationError`

已經有 authenticated principal，但 policy 不允許該操作。它不是 authentication failure，
在 FastAPI boundary 映射為 `403`。

### `InsufficientScopeError`

`PrincipalPolicy.enforce()` 發現缺少 OAuth scope 時 raise，並保存：

```python
error.required_scopes -> tuple[str, ...]
```

`FastAPISecurity` 會映射為 `403`，並加入 `WWW-Authenticate` 的
`error="insufficient_scope"` 資訊。

## Security errors

### `SecurityDependencyError`

JWT optional dependency 未安裝時 raise。安裝方式：

```powershell
uv add "fastapi-fin[security]"
```

### `AuthenticationError`

authentication layer 的基底錯誤。客製 authenticator 可以 raise 此類別，讓
`FastAPISecurity` 統一轉成 `401`。

### `MissingCredentialsError`

表示 request 沒有提供 credentials。適合給 framework-independent authentication service
使用；FastAPI adapter 會將缺少 bearer token 映射為 `401`。

### `InvalidTokenError`

表示 token 結構、signature、algorithm、issuer、audience、時間、type 或 claims 驗證失敗。
不應把底層 PyJWT exception 直接暴露給 API client。

## Adapter errors

### `AdapterError`

代表 FastAPI boundary 的設定或使用方式錯誤：

- `FastAPIAdapter.mount()` 收到需要 runtime 的 definition。
- endpoint 使用 `inject()` 卻沒有使用 `create_app()`。
- `FastAPISecurity` 的 authenticator、token URL 或 scope metadata 無效。
- 不支援的 adapter option。

此類錯誤應在 application wiring 階段修正，不應轉成一般 request response。

## Error handling boundary

推薦責任分配：

| Layer | 應處理 |
| --- | --- |
| Definition module | 修正 `DefinitionError` |
| Assembly/wiring | 修正 `AssemblyError`、`AdapterError` |
| Provider boundary | 記錄並處理 `ResolutionError` |
| Authentication boundary | 將 `AuthenticationError` 轉成未洩漏細節的 `401` |
| Authorization boundary | 將 `AccessDeniedError`、`AuthorizationError`、scope error 轉成 `403` |
| Application shutdown | 記錄 `ExceptionGroup` 中的全部 cleanup failures |
