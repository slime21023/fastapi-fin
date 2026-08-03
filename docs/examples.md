# 範例導讀

FastAPI-Fin 的範例由小到大展示 application definition、runtime 與 FastAPI Adapter
之間的關係。所有範例都使用目前 v1.0.0 的 public API，不依賴舊版 registry、controller、
module 或 metadata API。

## 建議學習順序

### 1. 先理解 route 與 Adapter boundary

閱讀 `01_minimal_routes.py`，注意 `ApplicationDefinition` 只描述 route，而
`FastAPIAdapter.mount()` 負責把 stateless route 掛到既有 FastAPI app。

### 2. 加入 provider 與 request dependency

閱讀 `02_dependency_injection.py`，理解 `provide()` 的 dependency list 與 endpoint
上的 `inject()` marker。接著閱讀 `06_scopes_and_cleanup.py`，比較
`APPLICATION` 與 `REQUEST` scope，以及 disposer 的生命週期。

### 3. 加入 request policy

閱讀 `03_guard_and_interceptor.py` 與 `09_complete_pipeline.py`：

- Guard 負責是否允許 request
- Interceptor 負責 middleware chain
- Guard、Interceptor 不需要 import FastAPI
- Adapter 只在 boundary 將 Guard rejection 轉成 HTTP 403

### 4. 使用 FastAPI 的資料驗證能力

閱讀 `05_request_response.py`，觀察 Pydantic request model、response model、query
parameter、status code 與 OpenAPI metadata 如何保留在 FastAPI boundary。

### 5. 使用獨立 feature

閱讀 `07_configuration.py` 與 `08_events_and_cache.py`。這些功能不需要啟動 FastAPI，
可以獨立測試或在其他 application layer 使用。

### 6. 理解 fail-fast assembly

閱讀 `10_validation_failures.py`，理解 duplicate route、missing provider 與 circular
dependency 為何會在 application 啟動前被拒絕。

### 7. 閱讀完整案例

最後閱讀 [`examples/complete_app/`](../examples/complete_app/README.md)。它將 domain、
providers、routes、policies、lifecycle 與 Adapter assembly 拆成多個檔案，展示實際
專案中如何維持 layer boundary。

## 執行所有範例

在專案根目錄執行：

```powershell
uv run python examples/01_minimal_routes.py
uv run python examples/02_dependency_injection.py
uv run python examples/03_guard_and_interceptor.py
uv run python examples/04_lifecycle_events.py
uv run python examples/05_request_response.py
uv run python examples/06_scopes_and_cleanup.py
uv run python examples/07_configuration.py
uv run python examples/08_events_and_cache.py
uv run python examples/09_complete_pipeline.py
uv run python examples/10_validation_failures.py
uv run python -m examples.complete_app
```

每個 executable example 都會自行建立 `TestClient` 或純 core runtime，並以 assertion
驗證結果；不需要啟動外部 server 或連接外部資料庫。
