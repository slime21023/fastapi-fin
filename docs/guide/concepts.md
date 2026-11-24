# 核心概念

FastAPI-Fin 以 Dishka 組裝服務，讓模組透過明確的契約合作；HTTP 層仍使用原生
FastAPI。服務契約描述程式碼如何取得與使用物件，不是描述 HTTP 請求與回應的
OpenAPI 契約。

## 從宣告到執行

```text
Module（providers、exports、requires）
    → Application（組合模組與替身）
    → build_container()（組裝並驗證 Dishka 依賴圖）
        ├─ FastAPIIntegration.lifespan → HTTP 請求使用 Inject[T]
        └─ open_container() → worker、指令稿或測試使用 await container.get(T)
```

| 名稱 | 責任 |
| --- | --- |
| 契約 | 用 `Protocol`、抽象基底類別或其他 Dishka 可識別的型別提示當作服務鍵。 |
| `Module` | 宣告一組 Dishka providers，並用 `exports` 與 `requires` 描述跨模組介面。 |
| `Application` | 組合模組，檢查模組名稱與匯出是否衝突，並記錄測試用替身。 |
| `AsyncContainer` | 由 Dishka 解析依賴、依 scope 快取實例並清理資源。 |
| `FastAPIIntegration` | 在 lifespan 開啟與關閉容器，透過 ASGI lifespan state 讓 `Inject` 存取當前 HTTP 請求的子容器。 |

## 宣告與資源生命週期

`Module` 和 `Application` 是凍結的宣告；`with_overrides()` 回傳新的 `Application`，
不修改原本的宣告。Dishka `Provider` 實例本身不會被深度凍結，應在組裝前完成其註冊。
組裝後的容器才持有各個 scope 的實例和清理狀態。

FastAPI-Fin 不另設 provider 裝飾器，也不替換 FastAPI 的 router、路由類別或 endpoint。
用 `Provider`、`@provide` 及 `Scope` 描述服務，再讓 `Inject[T]` 透過原生 `Depends`
將服務帶入路由。沒有 HTTP 時，直接以 `open_container()` 管理相同的依賴圖。

了解[模組邊界](modules.md)與[作用域和資源清理](scopes.md)。
