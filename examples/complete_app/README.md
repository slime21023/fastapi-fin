# Complete Task API

這是一個多檔案的完整使用案例，展示如何把 FastAPI-Fin 組合成一個可維護的
小型 application。它使用 in-memory repository，因此不需要資料庫或外部服務。

## 執行

在專案根目錄執行：

```powershell
uv run python -m examples.complete_app
```

成功時會印出 `complete_app: OK`。範例會用臨時金鑰簽發 JWT 並透過
`TestClient` 驗證：`GET /tasks` 不需登入；`POST /tasks` 缺少或帶入無效的
Bearer token 時回傳 `401`，有效 token 若沒有 `admin` 角色則回傳 `403`，
管理員可建立任務並在清單中看到結果。

## 閱讀順序

1. `domain.py`：Pydantic request/response models 與 `TaskService` Protocol。
2. `providers.py`：`tasks` module 以 dishka 提供內部的 APP-scope repository，
   只匯出 REQUEST-scope 的 `TaskService`；`auth` module 匯出
   `TokenAuthenticator`，由 `JwtVerifier` 實作。
3. `routes.py`：原生 `APIRouter` 用 `Inject[TaskService]` 取得服務，
   並用 `FastAPISecurity` 套用管理員角色規則。
4. `app.py`：`create_app(application)` 以 `FastAPIIntegration.lifespan`
   裝配 container 並掛載 router；`run_demo()` 組合 modules 並執行 HTTP 驗證。
