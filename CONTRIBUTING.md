# Contributing to FastAPI-Fin 1.0.0

## 開發環境

專案使用 `uv` 管理 Python、virtual environment 與 lockfile：

```powershell
uv sync --locked
uv run pre-commit install
```

快速驗證：

```powershell
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest
```

完整驗證：

```powershell
uv run bandit -q -r fastapi_fin
uv build
```

## 文件開發

文件使用 Zensical 編寫與建置。Markdown source 位於 `docs/`，網站導覽與建置設定位於
根目錄的 `zensical.toml`。

本地預覽：

```powershell
uv run zensical serve
```

執行嚴格建置檢查：

```powershell
uv run zensical build --strict
```

新增文件頁面後，必須同步更新 `zensical.toml` 的 `project.nav`。使用文件只描述目前
公開 API 與使用方式；API reference 依模組分布在 `docs/reference/`，可執行範例集中在
`examples/`。

## 架構規則

- `fastapi_fin.application` 只描述與驗證 immutable application definitions。
- `fastapi_fin.runtime` 只保存 application/request 執行期狀態。
- `fastapi_fin.features` 不依賴 FastAPI，並且可以獨立採用。
- 只有 `fastapi_fin.adapters` 可以 import 或呼叫 FastAPI API。
- Application model、route definitions、provider definitions 與 policies 不可變。
- Immutable definition models 使用 attrs 的 converter/validator；公開輸入仍統一拋出
  `DefinitionError`，不可直接依賴 attrs 的原生 `TypeError`／`ValueError`。
- 所有 declaration input 必須在建立時正規化；跨物件錯誤必須在 assembly 前拒絕。
- Runtime state 可以使用 attrs factory 簡化欄位初始化，但 lifecycle、cleanup 與 concurrency
  邏輯必須保持明確且可測試。
- Adapter 必須使用 FastAPI 公開 API，並保留 endpoint signature 與 OpenAPI 行為。
- 不新增舊版 API wrapper、deprecated alias 或 migration shim。

## 測試分層

- `tests/unit`：不 import 或啟動 FastAPI 的純邏輯測試。
- `tests/contract`：驗證 FastAPI Adapter 的 route、Depends、OpenAPI、HTTP error 與 lifespan。
- `tests/integration`：驗證完整 application definition 到 HTTP request 的流程。

新增功能前先決定它屬於 definition、runtime、feature 或 adapter layer；不要把 FastAPI
物件帶入 application、runtime 或 feature。

修改 DI、Guard、Interceptor、Events、Config 或 Adapter 時，應同步增加失敗路徑與 lifecycle
測試，並完成上述品質檢查。
