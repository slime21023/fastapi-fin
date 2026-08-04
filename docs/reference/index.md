# API Reference

本區是給需要理解組合規則、生命週期與錯誤契約的進階開發者使用的 API reference。
它不以快速入門為目標；第一次使用請先閱讀[安裝與第一個 App](../guide/getting-started.md)
與[核心概念](../guide/concepts.md)。

## Reference 範圍

| 頁面 | 內容 |
| --- | --- |
| [Application definitions](application.md) | Route、Router、Provider、Lifecycle 與 assembly |
| [Runtime](runtime.md) | `ApplicationRuntime`、`RequestContext` 與資源清理 |
| [FastAPI adapter](adapters.md) | `create_app()`、`mount()`、endpoint 轉換與 FastAPI 邊界 |
| [Security 與 JWT](security.md) | Principal、JWT、scope/role policy 與 FastAPI security bridge |
| [Features](features.md) | Guard、Interceptor、Event、Configuration、Cache |
| [Errors](errors.md) | 錯誤階層、發生時機與處理責任 |

## 公開 API 的匯入規則

以下是穩定的推薦匯入位置：

```python
from fastapi_fin.application import (
    ApplicationDefinition,
    ApplicationRouter,
    inject,
    provide,
    route,
)
from fastapi_fin.adapters import FastAPIAdapter, FastAPISecurity
from fastapi_fin.features import guard, interceptor
from fastapi_fin.security import JwtIssuer, JwtVerifier
```

根套件也重新匯出主要 API，但模組匯入能更清楚表達依賴邊界：

```python
from fastapi_fin import ApplicationDefinition, FastAPIAdapter
```

### Core 與 Adapter 的邊界

- `fastapi_fin.application`、`fastapi_fin.runtime`、`fastapi_fin.features` 與
  `fastapi_fin.security` 的核心實作不依賴 FastAPI。
- `fastapi_fin.adapters` 才負責 FastAPI `Depends`、`Security`、`Request`、OpenAPI 與
  HTTP exception mapping。
- 需要 provider 或 lifecycle 的 definition 使用 `FastAPIAdapter.create_app()`；只有
  stateless routes 才使用 `FastAPIAdapter.mount()`。

### Immutable 與 mutable 的邊界

`ApplicationDefinition`、`RouteDefinition`、`ProviderDefinition`、policy 與 feature
definition 都是在建立時驗證並正規化的 immutable value。`ApplicationRouter` 是
declaration-time builder；`ApplicationDefinition(routes=router)` 建立時會取得 snapshot。

只有 runtime state（例如 `ApplicationRuntime`、`RequestContext`、`CacheStore`）會在執行期
保存可變資料。不要把 runtime instance 放入共享 definition 或 module-level policy。

## API 穩定性與驗證時機

本 reference 針對目前公開的 `1.0.1` API。所有 public constructor、factory、decorator 與
registration method 都會在 declaration time 驗證輸入；常見失敗類型如下：

- definition 欄位錯誤：`DefinitionError`
- definition 彼此衝突：`AssemblyError`
- provider 執行或解析失敗：`ResolutionError`
- adapter 設定錯誤：`AdapterError`
- authentication/authorization 失敗：Security error hierarchy

完整錯誤階層與處理責任請參考 [Errors](errors.md)。
