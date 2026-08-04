# 測試

FastAPI-Fin 的測試可以依照是否需要 FastAPI 分層。

## Unit test

不啟動 FastAPI，測試 definition、assembly、runtime 與獨立 feature：

```python
from fastapi_fin.application import ApplicationDefinition, assemble, route


def test_definition_assembles() -> None:
    definition = ApplicationDefinition(
        routes=(route("/health", lambda: {"status": "ok"}),),
    )

    model = assemble(definition)

    assert len(model.routes) == 1
```

## FastAPI contract test

需要確認 route、OpenAPI、Depends、HTTP error 或 lifespan 時，使用 FastAPI 的
`TestClient`：

```python
from fastapi.testclient import TestClient


def test_health(app) -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
```

使用 context manager 能讓 startup、shutdown、provider disposer 都被執行。

## Integration test

Integration test 驗證完整流程：

```text
ApplicationDefinition
    → FastAPIAdapter.create_app()
    → lifespan startup
    → HTTP request
    → response
    → resource cleanup
```

專案中的 `examples/` 每個可執行範例都包含 assertion，並由
`tests/integration/test_examples.py` smoke test。

## 本地驗證

```powershell
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest
uv run zensical build --strict
```
