# 範例

在專案根目錄執行 `uv sync --locked`。每個範例驗證行為後印出自己的 `OK` 訊息。

| 指令 | 觀察重點 |
| --- | --- |
| `uv run python examples/01_modules_and_contracts.py` | 透過 Protocol 連接跨模組服務。 |
| `uv run python examples/02_scopes_and_finalization.py` | APP 和 REQUEST scope；成功與錯誤的清理。 |
| `uv run python examples/03_testing_overrides.py` | 用替身建立獨立測試 app。 |
| `uv run python examples/04_without_fastapi.py` | Worker 不經 HTTP 取得服務。 |
| `uv run python examples/05_validation_failures.py` | 契約衝突、缺失與未匯出的依賴。 |
| `uv run python examples/06_security_jwt.py` | 注入 authenticator 並使用 FastAPI bearer security。 |
| `uv run python -m examples.complete_app` | Task API 分離服務、認證與 HTTP。 |

