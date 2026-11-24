# FastAPI-Fin 範例

在專案根目錄執行 `uv sync --locked`，再執行：

```powershell
uv run python examples/01_modules_and_contracts.py
uv run python examples/02_scopes_and_finalization.py
uv run python examples/03_testing_overrides.py
uv run python examples/04_without_fastapi.py
uv run python examples/05_validation_failures.py
uv run python examples/06_security_jwt.py
uv run python -m examples.complete_app
```

前六支分別示範跨模組契約、資源清理、測試替換、不經 HTTP 解析、組裝失敗以及 JWT。
[完整 Task API](complete_app/README.md) 將服務、認證和 HTTP 路由分開組裝。
