# 核心概念

FastAPI-Fin 將「描述應用程式」與「執行應用程式」分開。使用者主要撰寫 definition，
Adapter 與 runtime 負責把 definition 轉成可執行的 FastAPI application。

## 四個主要名詞

### Definition

`ApplicationDefinition` 是使用者撰寫的應用程式宣告，內容包括：

- routes
- providers
- application-level guards
- application-level interceptors
- lifecycle hooks

definition 使用 attrs 建立 immutable snapshot。輸入會在建立時正規化與驗證。

`ApplicationRouter` 是 route module 的 declaration-time builder。它可以使用
FastAPI-like decorator 收集 routes。建立 `ApplicationDefinition` 時會自動取得
immutable snapshot；它不是 request-time registry。

### Assembly

`assemble()` 會檢查多個 definition 之間的關係，包括：

- 重複的 method/path
- 重複的 provider token
- provider 依賴不存在
- circular dependency
- application provider 依賴 request provider
- endpoint injection 找不到 provider

錯誤會在 application 啟動前提出，而不是等到 request 才發現。

### Runtime

`ApplicationRuntime` 保存一個 application 的可變執行狀態：

- application-scoped provider instance
- request-scoped provider instance
- provider disposer
- runtime startup/shutdown state

runtime 只應由 Adapter 或需要直接測試核心行為的程式碼管理。

### Adapter

`FastAPIAdapter` 是唯一負責 FastAPI 整合的邊界。它會：

- 將 routes 加入 FastAPI router
- 將 `inject()` 轉換成 FastAPI `Depends`
- 保留 endpoint signature 與 OpenAPI metadata
- 將 Guard rejection 轉成 HTTP 403
- 管理 FastAPI lifespan 與 runtime cleanup

## 執行流程

```text
ApplicationDefinition
        ↓
assemble()
        ↓
ApplicationModel（內部 immutable model）
        ↓
ApplicationRuntime + FastAPIAdapter
        ↓
FastAPI request
```

request 期間的主要順序是：

```text
FastAPI validation
        ↓
FastAPI Depends / provider resolution
        ↓
Guard
        ↓
Interceptor chain
        ↓
endpoint
        ↓
RequestContext cleanup
```

因此 request body validation 與 provider resolution 會先於 Guard。若需要在 validation
之前拒絕 request，應使用 FastAPI middleware 或其他適合的 boundary mechanism。

## Immutable 與 mutable 的分界

| 類型 | 是否可變 | 用途 |
| --- | --- | --- |
| `RouteDefinition` | 否 | 描述一條 route |
| `ProviderDefinition` | 否 | 描述 provider 與依賴 |
| `ApplicationDefinition` | 否 | 描述完整 application |
| `ApplicationModel` | 否 | assembly 後的內部模型 |
| `ApplicationRuntime` | 是 | 保存 application 執行狀態 |
| `RequestContext` | 是 | 保存單一 request 的 provider state |

這個分界讓 definition 可以被重複組裝與測試，而 runtime state 不會污染共享宣告。
