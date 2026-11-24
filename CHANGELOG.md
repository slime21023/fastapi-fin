# Changelog

## [2.0.0]

- 以 Dishka 取代自建 DI runtime。`Module` 宣告 `exports`／`requires`；`Application` 組裝產品與測試依賴。`with_overrides()` 可替換已匯出的契約。
- 在原生 FastAPI app 上以 `FastAPIIntegration.lifespan` 和 `Inject[T]` 啟用 DI，不需自訂 router、middleware 或 endpoint 包裝。
- 保留 JWT 與 principal policy；`FastAPISecurity` 現在由 `TokenAuthenticator` 契約取得認證實作，仍使用原生 OAuth2 scopes 與 HTTP 401／403。
- 移除 1.x 的 application definition、router、runtime、Guard、Interceptor、Events、Config 與 Cache，不保留相容性轉接層。

## [1.0.1] - 2026-08-03

### Added

- 新增 framework-independent `ApplicationRouter`。
- 支援 FastAPI-like route decorators、router prefix、tags 與 router composition。
- `ApplicationDefinition` 建構時自動 snapshot `ApplicationRouter`，一般 assembly 不需手動
  呼叫 `snapshot()`。
- 完整 Task API 範例改用 `ApplicationRouter` route module。

### Changed

- immutable application definitions 與 feature definitions 改用 attrs converter/validator，
  集中 normalization 並保留 `DefinitionError` 公開錯誤語義。
- `Configuration` 的 parsed values 改為真正的 read-only snapshot。
- runtime 使用 attrs factory 簡化 mutable state 初始化，但保留明確 lifecycle、cleanup 與
  concurrency 控制。
- 新增 attrs runtime dependency 與對應的 immutable model regression tests。

## [1.0.0] - 2026-08-03

第一個穩定版本。

### Changed

- 以 clean-slate 架構重寫 application assembly。
- 以 `ApplicationDefinition` 取代 registry、controller/module metadata 與 decorator graph。
- 以內部 immutable `ApplicationModel` 取代 compiler/compiled application terminology。
- 以 `ApplicationRuntime` 與 `RequestContext` 取代舊版 DI runtime。
- Provider 改為明確 dependency list，scope 收斂為 `APPLICATION` 與 `REQUEST`。
- FastAPI Adapter 改為 `create_app()` 與 stateless `mount()` 兩個明確入口。
- Guard、Interceptor、Events、Config 與 Cache 改成獨立 feature modules。
- Lifecycle hooks 與 domain event bus 分離。
- 移除所有舊版 API、舊版 exports、migration wrapper 與相容性 shim。
- 重新建立 unit、contract 與 integration 測試。

### Removed

- `ApplicationRegistry`
- `MetadataSnapshot`、`CompiledApplication` 與舊 metadata models
- controller/module decorators 與 convenience route decorators
- transient scope、隱式 annotation provider graph 與 `ContextVar` controller state
- 舊版 EventDispatcher lifecycle integration
