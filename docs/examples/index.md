# 範例

範例由小到大展示 route definition、runtime、FastAPI Adapter 與完整 application
assembly。所有範例都可以在 repository 根目錄直接執行，不需要外部資料庫或 server。

## 建議閱讀順序

1. [最小 routes](https://github.com/slime21023/fastapi-fin/blob/main/examples/01_minimal_routes.py)
2. [Dependency Injection](https://github.com/slime21023/fastapi-fin/blob/main/examples/02_dependency_injection.py)
3. [Guard 與 Interceptor](https://github.com/slime21023/fastapi-fin/blob/main/examples/03_guard_and_interceptor.py)
4. [Lifecycle hooks](https://github.com/slime21023/fastapi-fin/blob/main/examples/04_lifecycle_events.py)
5. [Request、response 與 OpenAPI](https://github.com/slime21023/fastapi-fin/blob/main/examples/05_request_response.py)
6. [Scopes 與 cleanup](https://github.com/slime21023/fastapi-fin/blob/main/examples/06_scopes_and_cleanup.py)
7. [Configuration](https://github.com/slime21023/fastapi-fin/blob/main/examples/07_configuration.py)
8. [EventBus 與 CacheStore](https://github.com/slime21023/fastapi-fin/blob/main/examples/08_events_and_cache.py)
9. [完整 pipeline](https://github.com/slime21023/fastapi-fin/blob/main/examples/09_complete_pipeline.py)
10. [Validation failures](https://github.com/slime21023/fastapi-fin/blob/main/examples/10_validation_failures.py)
11. [Security 與 JWT](https://github.com/slime21023/fastapi-fin/blob/main/examples/11_security_jwt.py)

## 完整多檔案案例

[Complete Task API](https://github.com/slime21023/fastapi-fin/tree/main/examples/complete_app)
將 domain models、providers、routes、policies、lifecycle 與 app assembly 分成不同檔案，
適合在閱讀前面範例後參考實際專案組織方式。

## 執行範例

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
uv run python examples/11_security_jwt.py
uv run python -m examples.complete_app
```
