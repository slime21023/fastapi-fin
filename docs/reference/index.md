# API 參考

本區說明 FastAPI-Fin 2.0 的公開 API、組裝規則及錯誤責任。第一次使用請先閱讀[快速入門](../guide/getting-started.md)與[核心概念](../guide/concepts.md)。

| 頁面 | 內容 |
| --- | --- |
| [模組與容器](modules.md) | `Module`、`Application`、合約覆寫、Dishka 容器與 context |
| [FastAPI 整合](fastapi.md) | `Inject[T]`、`FastAPIIntegration.lifespan` 與啟動驗證 |
| [Security 與 JWT](security.md) | `TokenAuthenticator`、JWT、principal、policy 與 `FastAPISecurity` |
| [錯誤](errors.md) | 例外階層、發生時機與處理責任 |

## 匯入位置

- `fastapi_fin` 匯出模組、容器、adapter 與安全性公開 API。
- `fastapi_fin.adapters` 提供 FastAPI 整合；根套件按需載入這些匯出。
- `fastapi_fin.security` 提供不依賴 FastAPI 的認證合約、JWT、principal、policy 和安全性例外。
- `fastapi_fin.errors` 定義共用的基底、宣告、組裝與 adapter 例外。
- `Provider`、`provide`、`Scope` 與容器操作由 `dishka` 提供；請直接使用 Dishka 的 API。

核心負責模組合約與容器組裝；adapter 把容器接到 FastAPI 的 lifespan 與依賴機制。路由宣告、請求與回應驗證、OpenAPI 仍由 FastAPI 負責。
