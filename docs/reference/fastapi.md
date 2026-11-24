# FastAPI 整合

`FastAPIIntegration`、`Inject`、`CONTAINER_STATE_KEY` 和 `FastAPISecurity` 可從 `fastapi_fin` 或 `fastapi_fin.adapters` 匯入。認證與授權 API 另見[安全性參考](security.md)。

## `FastAPIIntegration(application)`

`application` 必須是 `Application`，否則拋出 `AdapterError`。整合物件不可重新賦值；實際的容器在 lifespan 啟動時才建立。

### `lifespan(app)`

```python
integration = FastAPIIntegration(application)
app = FastAPI(lifespan=integration.lifespan)
```

這個非同步 context manager 接收 `FastAPI` 實例，啟動時建立新的 Dishka 容器、檢查路由的注入，並 yield `dict[str, object]`。整合物件擁有根容器，離開 lifespan 時關閉它。傳入其他型別會拋出 `AdapterError`。

`CONTAINER_STATE_KEY` 值為 `"fastapi_fin_container"`，是 lifespan state 字典中根容器的鍵，不是 `app.state` 欄位。組合自己的 lifespan 時，應保留這個鍵和值，讓 ASGI 將它傳入 `request.state`。完整用法見 [FastAPI 整合指南](../guide/fastapi.md)。

### 啟動驗證範圍

- 檢查 FastAPI HTTP 路由能辨識的 `Inject`，包含參數、巢狀 `Depends` 或 `Security`，及路由與 router 設定的依賴。偵測到未匯出的合約會拋出 `AssemblyError`。
- WebSocket 不支援 `Inject`；啟動時偵測到使用會拋出 `AdapterError`。
- 不走訪 mounted sub-app 的路由。掛載的 HTTP routes 可以從宿主 ASGI lifespan state 取得容器，但其注入不會由宿主在啟動時驗證。

## `Inject[T]`

在參數註記中使用 `Inject[T]`，其中 `T` 是已匯出的服務合約。對型別檢查器而言參數型別為 `T`；執行期建立 `Annotated[T, Depends(...)]`，由 FastAPI 執行依賴，從 Dishka REQUEST scope 取得物件。同一 HTTP request 內的注入共用同一個 REQUEST scope。字串、`None` 或不可雜湊的合約鍵會拋出 `AdapterError`；請求時找不到作用中的根容器也會拋出 `AdapterError`。

`Request` 由整合宣告為 `Scope.REQUEST` 的 context，並在開啟請求 scope 時放入當前請求。模組如需在 provider 中使用它，可宣告 `requires=(Request,)`；endpoint 則可直接用 FastAPI 原生的 `request: Request`，不使用 `Inject[Request]`。

整合不新增 middleware、不改寫 route class、不包裝 endpoint。`Inject[T]` 本身不會成為 OpenAPI 請求參數或 request body；路由、驗證、OpenAPI 與例外處理仍由 FastAPI 管理。
