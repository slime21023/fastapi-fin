# 模組與容器

以下 API 皆可從 `fastapi_fin` 匯入，不依賴 FastAPI。Provider、scope、解析與資源生命週期使用 Dishka 的 API。

## `Module`

```python
Module(
    name: str,
    providers: tuple[Provider, ...] = (),
    exports: tuple[object, ...] = (),
    requires: tuple[object, ...] = (),
)
```

- `name` 去除前後空白後必須非空，並作為 Dishka component 名稱。空字串保留給 Dishka 預設 component。
- `providers` 為 Dishka `Provider` 實例。不要自行為 provider 設定非預設 component 或使用 `from_context`；前者由模組分配，後者由容器宣告。
- `exports` 列出其他模組和呼叫端可取得的服務合約；`requires` 列出要從其他模組或傳入的 context 取得的合約。這裡的合約是可作為 Dishka 鍵的型別提示（例如 `Protocol`、ABC 或具體型別），不是 OpenAPI schema。
- 合約鍵不得是字串或 `None`，也必須可雜湊。同一欄位不能有重複鍵，模組也不能同時匯出及匯入同一鍵。

集合輸入正規化成 tuple；宣告不可重新賦值，但不是 provider 實例的深層複本。欄位錯誤會拋出 `DefinitionError`。

## `Application`

```python
Application(modules: tuple[Module, ...] = (), overrides: Mapping[object, object] = {})
```

`modules` 正規化成 tuple，且只接受 `Module`。`exports` 是唯讀的 `Mapping[object, str]`，從合約映射至匯出模組名稱。`overrides` 是唯讀的淺層快照，從合約映射至替代實例。

重複模組名稱、跨模組重複匯出合約，或覆寫未匯出的合約，會在建立 `Application` 時拋出 `AssemblyError`。`requires` 是否滿足，要等到建置容器時才檢查，因為當時才知道 context 宣告。

### `with_overrides(overrides)`

接收 `Mapping[object, object]`，回傳新的 `Application`；原物件不變，同鍵以新值為準。替代實例在 APP scope 可用，對預設 component、匯出模組本身及透過 `requires` 匯入的模組都生效。容器使用呼叫端提供的實例，不負責其清理，也不會呼叫原合約 factory 來產生替身。

## `build_container()` 與 `open_container()`

```python
build_container(application, *, context={}) -> AsyncContainer
open_container(application, *, context={})  # async context manager，yield AsyncContainer
```

`application` 必須是 `Application`。`context` 是從合約鍵映射至 Dishka `BaseScope` 的 `Mapping[object, BaseScope]`，用來宣告值的型別與所在 scope，不是值本身。例如 `context={Job: Scope.REQUEST}`，之後用 `async with root(context={Job: job}, scope=Scope.REQUEST) as request:` 傳入值。這兩個函式不接受 APP scope 的 context 值。

預設 component 可解析匯出合約與已宣告的 context；各模組預設在自身 component 解析，並藉 `requires` 取得組裝時建立的匯入 alias。容器不會替一般的未匯出依賴建立跨 component 的 alias；這不是權限控制，不會阻止程式使用 Dishka 明確指定 component 的方式取用物件。

無效 context 宣告會拋出 `DefinitionError`。未滿足的 `requires`、context 與匯出鍵衝突，或不是 `Application` 的輸入會拋出 `AssemblyError`。建置使用 Dishka 的嚴格驗證；`InvalidGraphError` 與 `AliasedFactoryNotFoundError` 會包裝成 `AssemblyError`，其餘 Dishka 例外不作此轉換。

呼叫 `build_container()` 後，根容器由呼叫端負責 `await container.close()`；使用 `async with open_container(...)` 則會在離開時自動關閉。子 scope 由進入該 scope 的程式碼管理。容器是非同步的；同步 factory 仍可使用，但在事件迴圈上直接執行。

參見[模組指南](../guide/modules.md)、[生命週期與 scope](../guide/scopes.md)與[錯誤](errors.md)。
