# Contributing to FastAPI-Fin

## 開發環境

專案使用 `uv` 管理 Python、virtual environment 與 lockfile：

```powershell
uv sync --locked
uv run pre-commit install
```

日常快速迴圈：

```powershell
uv run ruff format .
uv run ruff check .
uv run ty check
uv run pytest -m "not slow and not integration"
```

完整驗證：

```powershell
uv run pre-commit run --all-files
uv run bandit -q -r fastapi_fin
uv run pytest --cov=fastapi_fin --cov-report=term-missing --cov-fail-under=85
uv build
```

依賴變更後必須執行 `uv lock`，並確認 `uv lock --check` 與 `pip-audit --strict`
都通過。不要直接使用 `pip install` 或手動修改 `uv.lock`。

## 架構規則

- `fastapi_fin.core` 只依賴標準函式庫與 `attrs`，不可 import FastAPI、Starlette 或 Pydantic。
- `fastapi_fin.application` 只負責宣告、metadata 與 framework-independent compiler。
- `fastapi_fin.adapters` 是唯一可呼叫 FastAPI API 的邊界。
- metadata、policy、subscription、binding 與 config 使用 immutable attrs snapshot。
- 執行期 cache、request context 與 resource lifecycle state 才可以是 mutable runtime state。

新增功能時，先建立 core value object 與宣告期驗證，再於 Adapter 增加框架轉譯；不要
讓 core 為了方便而依賴 FastAPI 物件。

## Agent skills

專案專用 skills 位於 `.agents/skills/`：

- `fastapi-fin-architecture`：檢查分層、attrs immutability 與 Adapter 邊界。
- `fastapi-fin-testing`：決定 unit、contract、integration 測試層級。
- `fastapi-python`：FastAPI 與 async endpoint 實作慣例。
- `python-quality`：Ruff、ty 與靜態品質檢查。
- `python-type-hints`：公共 API 型別設計。
- `reviewing-python-libraries`：package、security、CI 與發行面檢查。

修改 core、application 或 Adapter 時，應先閱讀對應 skill 的 `SKILL.md`，並在提交前
完成相關測試層級與完整品質閘門。
