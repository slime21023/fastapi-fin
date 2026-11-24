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

Ruff 檢查型別註解、文件字串、函式複雜度、未使用參數、行長與安全規則。若框架契約或測試資料確有例外，請在最小範圍註明規則編號與原因。

## 迴圈與效能

除非演算法必要（例如遞迴走訪依賴樹），避免巢狀迴圈，包括巢狀 comprehension 與在迴圈內對 `tuple`／`list` 做 `in` 查詢。改用 `set`／`dict` 查詢、集合運算，或以 `itertools.chain.from_iterable` 展平後單層迭代；每層迴圈拆成有名字的小函式。`tests/test_code_rules.py` 會檢查 `fastapi_fin/` 與 `examples/` 中的巢狀迴圈（`in` 查詢需人工審查）。

## 架構邊界

- `fastapi_fin/modules.py` 驗證不可變的 module/application 宣告；provider 建好後交給 module，不再原地修改。
- `fastapi_fin/container.py` 把 exports 和 requires 連到 Dishka components。由 Dishka 負責依賴圖、作用域、快取與清理，不重作 runtime。
- `fastapi_fin/security/` 的 JWT、principal、policy 和 authenticator contract 不依賴 FastAPI。
- 函式庫中只有 `fastapi_fin/adapters/` 可 import FastAPI。整合走原生 dependency 與 lifespan，不使用 `dishka.integrations`、自訂路由或 middleware。
- 組裝階段保留原始 Dishka graph 錯誤為 cause；執行時不包裝 factory 例外。

## 測試與文件

- Unit：`tests/unit` 驗證契約、作用域與 JWT，不啟動 FastAPI。
- Contract：`tests/contract` 使用 `with TestClient(app)` 驗證 HTTP/OpenAPI、lifespan 與認證行為。
- Integration：`uv run pytest -m integration` 執行所有範例，並以真實的 Uvicorn 伺服器驗證 lifespan 的啟動、關閉與多 worker 行為（`tests/integration/test_uvicorn.py`）。CI 單獨執行這一步，其餘測試以 `-m "not integration"` 執行。
- 更新 `docs/` 時同步更新 `zensical.toml` 導覽；以 `uv run zensical serve` 本地預覽。

## 發布

目前沒有自動發布的 workflow，發布步驟如下：

1. 在 `pyproject.toml` 與 `fastapi_fin/__init__.py` 同步版本號（`tests/test_package.py` 會檢查），更新 `CHANGELOG.md`，執行 `uv lock`。
2. 推送並確認 CI 全數通過。
3. 執行 `uv build` 與 `uvx twine check dist/*`；檢查 wheel 只含 `fastapi_fin/` 與授權檔，sdist 不含 `.agents/`。
4. 建立並推送 tag：`git tag v<版本> && git push origin v<版本>`。
5. 以 `uv publish` 上傳（需要 PyPI token）。

