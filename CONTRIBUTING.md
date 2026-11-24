# Contributing to FastAPI-Fin

## 開發環境

```powershell
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest --cov=fastapi_fin --cov-fail-under=85
uv run bandit -q -r fastapi_fin
uv run zensical build --strict
uv build
```

## 架構邊界

- `fastapi_fin/modules.py` 驗證不可變的 module/application 宣告；provider 建好後交給 module，不再原地修改。
- `fastapi_fin/container.py` 把 exports 和 requires 連到 Dishka components。由 Dishka 負責依賴圖、作用域、快取與清理，不重作 runtime。
- `fastapi_fin/security/` 的 JWT、principal、policy 和 authenticator contract 不依賴 FastAPI。
- 函式庫中只有 `fastapi_fin/adapters/` 可 import FastAPI。整合走原生 dependency 與 lifespan，不使用 `dishka.integrations`、自訂路由或 middleware。
- 組裝階段保留原始 Dishka graph 錯誤為 cause；執行時不包裝 factory 例外。

## 測試與文件

- Unit：`tests/unit` 驗證契約、作用域與 JWT，不啟動 FastAPI。
- Contract：`tests/contract` 使用 `with TestClient(app)` 驗證 HTTP/OpenAPI、lifespan 與認證行為。
- Integration：`uv run pytest -m integration` 執行所有範例，確認輸出與實際結果。
- 更新 `docs/` 時同步更新 `zensical.toml` 導覽；以 `uv run zensical serve` 本地預覽。

