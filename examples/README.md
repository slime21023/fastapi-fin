# FastAPI-Fin 1.0.0 examples

每個範例都可以直接執行：

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

建議依序閱讀：

1. `01_minimal_routes.py`：明確 route definition 與既有 FastAPI app 掛載
2. `02_dependency_injection.py`：Application provider 與 `inject()`
3. `03_guard_and_interceptor.py`：Guard 與 Interceptor
4. `04_lifecycle_events.py`：Adapter 管理的 startup/shutdown hooks
5. `05_request_response.py`：Pydantic request/response validation 與 OpenAPI metadata
6. `06_scopes_and_cleanup.py`：Application/request scope 與 disposer 順序
7. `07_configuration.py`：設定 parser、default 與 sensitive value redaction
8. `08_events_and_cache.py`：framework-independent EventBus 與 CacheStore
9. `09_complete_pipeline.py`：組合 DI、Guard、Interceptor 與 lifecycle
10. `10_validation_failures.py`：assembly 前的錯誤驗證

最後閱讀 [complete_app/README.md](complete_app/README.md)，了解如何將這些概念
拆分成多個可維護的 application modules。

1.0.0 不再使用 controller、module、registry 或舊版 metadata API。
