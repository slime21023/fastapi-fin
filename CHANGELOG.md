# Changelog

本檔案記錄 FastAPI-Fin 的公開變更。

## Unreleased

### Added

- framework-independent application compiler，提供 immutable `CompiledApplication`
  與 `CompiledRoute`，並讓 FastAPI Adapter 透過 compiler 完成路由組裝。
- async lazy singleton 的並發初始化去重，避免同一 service 被重複建立。
- root package 對 FastAPI Adapter exports 改為 lazy loading，讓 core/application 可獨立載入。
- Adapter 將 request-time `ResolutionError` 轉譯為不洩漏內部細節的 generic HTTP 500。
- Config optional settings 支援經 parser 正規化的 immutable default values。
- Config parser 在 `load()` 與 `replace()` 使用一致的錯誤轉譯邊界。
- Interceptor timeout 套用至純同步 pipeline 時會在組裝階段明確拒絕。
- Guard predicate 非布林結果會被拒絕，避免授權條件因 truthy 值而意外放行。
- DI factory annotations 支援 `typing.Annotated` service tokens。
- Route declarations 支援 framework-independent OpenAPI／HTTP options，包含 response model、status code、tags 與 operation metadata。
- `ConfigSnapshot.__repr__()` 會遮罩 sensitive setting values，避免診斷輸出洩漏 secrets。
- Interceptor 同步 pipeline 會拒絕執行期間動態產生的 coroutine，避免未 await 結果穿透邊界。
- Guard 與 Event 的同步 API 會在拒絕 async callable 時關閉已建立的 coroutine；pytest warnings gate 同步提升為 errors。
- retry、timeout、cache TTL、priority 與 snapshot version 增加嚴格數值驗證，拒絕 `bool` 與非有限 timeout／TTL。
- 新增 immutable `EventDescriptor`，支援事件型別檢查與 handler 前 normalization；既有 event type 訂閱 API 保持相容。
- 移除已不再使用的 legacy authentication runtime dependencies，縮小 package 安裝與安全稽核面。
- `CacheStore` 的 execution state 增加同步保護，支援同步 endpoint thread pool 的併發 lookup/store/eviction。
- 新增 `CONTRIBUTING.md` 與 legacy API 遷移指南，說明 uv/tooling、agent skills 與 core／Adapter 分層邊界。
- 將既有 `get_route_metadata()` getter 加入 core 與 root package 的穩定 public exports。
- 將 FastAPI Adapter 拆分為 `fastapi_fin.adapters` 下的 application、router、dependencies
  與 lifespan 邊界模組。
- ContainerRuntime 的 sync／async lazy singleton 都加入並發初始化去重，避免 thread pool
  或 event loop 下重複建立同一個 singleton。
- `ResolutionContext` 新增 `with`／`async with` 支援，自動管理 request/transient resource cleanup。
- `FastAPIAdapter(app).include(registry)` 明確提供 route-only 掛載；配置 runtime/event
  lifecycle 時會 fail fast，要求使用 `FastAPIAdapter.create_app(...)` 避免啟停 cleanup
  被跳過。
- CI 版本矩陣改為明確驗證相容的 FastAPI／Starlette 配對，並涵蓋 Python 3.12／3.13。
- EventDescriptor normalizer 支援 async callable，`publish_async()` 會在 handler 前完成
  normalization；同步 dispatch 對 async normalizer 會 fail fast。
- Application decorators 對非 iterable 的 controller/module composition options 統一拋出
  `DeclarationError`，不再洩漏原生 `TypeError`。
- FastAPIAdapter 建構參數與 lifespan handler 增加 declaration-time `AdapterError` validation。
- MetadataRegistry/MetadataSnapshot 對錯誤 controller metadata 與非 iterable registration input
  統一拋出 `RegistrationError`，避免洩漏原生 `TypeError`/`AttributeError`。
- DI sync cleanup 遇到 async-only resource 時會保留 state，允許後續以 `close_async()` 完成
  cleanup，避免錯誤路徑造成 resource leak。

## [0.1.0] - 2026-08-02

### Added

- attrs-based immutable metadata、DI、Guard、Interceptor、Event 與 Config 核心模型。
- FastAPI Adapter，支援 routing、Depends、lifespan、OpenAPI 與 request-safe Controller lifecycle。
- DI singleton、transient、request scope、eager initialization 與 resource cleanup。
- 完整 HTTP method convenience decorators。
- uv、Ruff、ty、pytest、pre-commit 與 FastAPI compatibility CI 基礎設施。
- Bandit static scan 與 pip-audit dependency security gate。
