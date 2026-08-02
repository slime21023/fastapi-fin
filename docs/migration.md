# Legacy API 遷移指南

目前 package 以 attrs-based architecture 為主要契約。舊版的 `middleware.py`、
`permission.py`、`helper/`、`provider/` 與 `health.py` 不再是目前
package 的公開 API；直接搬回這些模組會讓 FastAPI、Pydantic 或第三方 authentication
實作滲入 core，違反新的分層規則。

## 能力對應

| 舊版用途 | 新架構入口 |
|---|---|
| route/controller/DI 組裝 | `ApplicationRegistry`、`.module()`、`.controller()`、`.provide()` |
| permission rule | `GuardRule`、`GuardPolicy`、Adapter route dependency |
| advanced service dependency | `Scope`、`dependency` |
| cross-cutting logic | `InterceptorSpec`、`InterceptorChain` |
| startup/shutdown callback | `EventDispatcher`、`ApplicationStarted`、`ApplicationStopping` |
| typed configuration | `SettingSpec`、`ConfigSnapshot` |
| FastAPI route integration | `FastAPIAdapter(app).include(registry)` |

舊版若以 `FastAPIAdapter(...).inject(Token)` 建立 dependency，請改為
`Depends(dependency(Token))`，並將 `Token` 的 Provider 放入同一個
`ApplicationRegistry`。新的 dependency 會從目前 FastAPI app 取得唯一 Runtime，避免
手動建立的 Adapter 與 application lifespan 使用不同 Singleton cache。

## Authentication、CSRF 與外部 provider

JWT、OAuth/OIDC、CSRF 與 session middleware 不屬於目前 core domain model。若應用需要
這些能力，請在自己的 FastAPI Adapter／application layer 或獨立 package 實作，再以
`GuardSubjectProvider`、DI service 或標準 FastAPI middleware 接入。不要把 JWT library、
Starlette middleware 或 Pydantic model import 到 `fastapi_fin.core`。

這個邊界讓 FastAPI-Fin 可以維持 framework-independent 的 DI、Guard、Interceptor、
Event 與 Config 核心，也避免 package 被不相關的 authentication dependency 綁定。
