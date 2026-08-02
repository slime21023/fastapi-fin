# FastAPI-Fin examples

每個範例都是可直接執行的 Python script，使用 FastAPI `TestClient` 驗證結果，
不需要另外啟動 web server：

```powershell
uv run python examples/01_minimal_routes.py
uv run python examples/02_dependency_injection.py
uv run python examples/03_guard_and_interceptor.py
uv run python examples/04_lifecycle_events.py
```

第一個範例刻意以原生 FastAPI 為入口，再掛載 FastAPI-Fin；其餘範例展示擴展功能：

1. FastAPI-first 路由與 OpenAPI 組裝
2. `ApplicationRegistry` 與 `attrs` 架構下的 Provider DI
3. Guard 與 Interceptor 的宣告式組合
4. Application lifespan 與 typed events

`01_minimal_routes.py` 同時包含原生的 `/health` route 與 FastAPI-Fin 的
`/api/users/{user_id}` route，兩者共存於同一個 FastAPI app。

不需要 Container lifecycle 或 EventDispatcher 時，使用
`FastAPIAdapter(app).include(registry)`；需要管理
startup/shutdown 資源時，才使用 `create_app()`，如 DI 範例所示。

每個檔案都刻意維持在一個小範圍內，適合先修改再重新執行，觀察 API 的使用感受。
