# Complete Task API

這是一個多檔案的完整使用案例，展示如何把 FastAPI-Fin 組合成一個可維護的
小型 application。它使用 in-memory repository，因此不需要資料庫或外部服務。

## 執行

在專案根目錄執行：

```powershell
uv run python -m examples.complete_app
```

## 閱讀順序

1. `domain.py`：Pydantic request/response models
2. `providers.py`：application/request provider 與 disposer
3. `routes.py`：`ApplicationRouter`、endpoint 與 `inject()`
4. `policies.py`：Guard 與 Interceptor
5. `lifecycle.py`：startup/shutdown hooks
6. `app.py`：ApplicationDefinition 組裝與 HTTP smoke test

這個案例刻意將 FastAPI 只放在 `app.py` 的 Adapter boundary；domain、provider
與 policy 可以在不啟動 FastAPI 的情況下理解與測試。
