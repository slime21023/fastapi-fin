# Changelog

格式參考 [Keep a Changelog](https://keepachangelog.com/)。

## [0.9.1] - 2026-11-24

第一個公開發布的版本。

### Added

- `Module` 以 `exports`／`requires` 宣告模組的公開契約與跨模組依賴；`Application` 組合模組並驗證重複的模組名稱與匯出。
- `build_container()` 與 `open_container()` 以 Dishka 組裝容器：每個模組是獨立的 component，只能透過匯出的契約互相取用；組裝時以 Dishka 嚴格驗證依賴圖，圖錯誤以 `AssemblyError` 回報並保留原始例外為 `__cause__`。Provider、`Scope` 與資源清理直接使用 Dishka 的 API。
- `Application.with_overrides()` 以契約為單位替換實作（APP scope 的外部實例），對 HTTP 注入、其他模組與匯出模組本身一致生效。
- `FastAPIIntegration.lifespan` 與 `Inject[T]` 以原生 FastAPI `Depends` 注入服務：不加 middleware、不改 route class、不包裝 endpoint。啟動時掃描路由，注入未匯出的契約會拋出 `AssemblyError`，WebSocket 使用 `Inject` 會拋出 `AdapterError`。
- 安全性：`TokenAuthenticator` 契約、`JwtIssuer`／`JwtVerifier`／`JwtKeySet`、不可變的 `AuthenticatedPrincipal` 與 `PrincipalPolicy`（`require_scopes`／`require_roles`），以及整合 OAuth2 scopes 與 HTTP 401／403 語意的 `FastAPISecurity`。JWT 支援透過 `fastapi-fin[security]` 選用安裝。
- 與 Uvicorn 搭配使用：命令列單行程與 `--workers N`、優雅關閉後的資源清理，以及路由注入未匯出契約時拒絕啟動；詳見部署指南。
- 使用指南、API 參考與可執行範例（含完整的 Task API）。

### Compatibility

- Python 3.12 與 3.13。
- 已測試 FastAPI 0.115.11（Starlette 0.46.2）、0.141.1（Starlette 1.3.1）與 0.165.0；Dishka 1.10.1（宣告範圍 `>=1.10.1,<2`）；attrs 25.4.0 與目前鎖定版；PyJWT 2.10.0 與目前鎖定版。
- CI 在 Linux 執行；Windows 於本機驗證。
