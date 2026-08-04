# 公開 API

## Application

| API | 用途 |
| --- | --- |
| `ApplicationDefinition` | 描述完整 application |
| `ApplicationRouter` | 以 decorator 語法收集並分組 routes |
| `RouteDefinition` | 描述單一 route |
| `ProviderDefinition` | 描述 provider 與依賴 |
| `LifecycleDefinition` | 描述 startup/shutdown hooks |
| `route()` | 建立 route definition |
| `ApplicationRouter.snapshot()` | 低階取得 immutable route tuple；一般 assembly 不需手動呼叫 |
| `provide()` | 建立 provider definition |
| `inject()` | 在 endpoint 標記 provider injection |
| `assemble()` | 驗證並建立 application model |
| `HttpMethod` | 支援的 HTTP methods |
| `Scope` | `APPLICATION` 或 `REQUEST` |

## Runtime

| API | 用途 |
| --- | --- |
| `ApplicationRuntime` | 管理 application-scoped state 與 runtime lifecycle |
| `RequestContext` | 管理單一 request 的 provider state 與 cleanup |

一般 FastAPI application 不需要直接建立 runtime；請使用
`FastAPIAdapter.create_app()`。

## FastAPI Adapter

| API | 用途 |
| --- | --- |
| `FastAPIAdapter.create_app()` | 建立並管理完整 FastAPI application |
| `FastAPIAdapter.mount()` | 將 stateless routes 掛入既有 FastAPI app |
| `Lifespan` | 自訂 FastAPI lifespan callable 的型別別名 |

## Security

| API | 用途 |
| --- | --- |
| `AuthenticatedPrincipal` | 保存已驗證的 immutable identity 與 claims |
| `JwtIssuer` | 使用明確 algorithm 與 registered claims 簽發 JWT |
| `JwtVerifier` | 驗證 signature、issuer、audience、expiry 與 token type |
| `JwtKeySet` | 以 `kid` 對 trusted immutable key set 進行 key rotation |
| `PrincipalPolicy` | 定義 scope、role authorization requirements |
| `require_scopes()` / `require_roles()` | 建立 authorization policy |
| `FastAPISecurity` | 整合 FastAPI bearer、Security scopes 與 HTTP errors |

## Policies

| API | 用途 |
| --- | --- |
| `GuardDefinition` / `guard()` | 建立授權 predicate |
| `enforce_guards()` | 在 framework-independent layer 執行 Guard |
| `InterceptorDefinition` / `interceptor()` | 建立 middleware chain handler |
| `execute_interceptors()` | 執行 interceptor chain |

## Optional features

| API | 用途 |
| --- | --- |
| `SettingDefinition` | 定義設定欄位與 parser |
| `Configuration` | 載入 immutable parsed settings |
| `EventSubscription` | 定義 event handler subscription |
| `EventBus` | 發布同步或非同步事件 |
| `CachePolicy` | 定義 cache TTL 與容量限制 |
| `CacheStore` | 提供 thread-safe in-process cache |

## 公開錯誤

| 錯誤 | 說明 |
| --- | --- |
| `DefinitionError` | definition 欄位或 feature input 無效 |
| `AssemblyError` | definition 之間無法形成有效 application model |
| `AdapterError` | FastAPI Adapter 使用方式無效 |
| `ResolutionError` | provider 無法解析或 factory 失敗 |
| `RuntimeClosedError` | application 或 request runtime 已關閉 |
| `AccessDeniedError` | Guard 拒絕 subject |
