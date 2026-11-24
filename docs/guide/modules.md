# 模組與契約

先以 `Protocol`、抽象基底類別或其他 Dishka 可識別的型別提示定義服務契約，再讓模組註冊實作。契約是 DI 鍵；若工廠回傳型別是具體類別，請用 `@provide(provides=Contract, scope=...)` 明確指定要註冊的鍵。

- `providers`：傳入 Dishka `Provider` 實例，由 `Module` 將它們分配到同名的 Dishka component，不要預先設定 provider 的 component。
- `exports`：公開給其他模組與 HTTP 層的契約。每個契約只能由一個模組匯出，且必須可由該模組提供。
- `requires`：列出要由其他模組或宿主取得的契約。一般 provider 參數仍使用契約型別，不需指定 component。

## 跨模組注入

延續[快速入門](getting-started.md)，在同一個 `app.py` 中加上 `profiles` 模組。`ProfileService` 依賴 `UserDirectory` 而非資料來源的實作；`profiles` 需要明列 `UserDirectory`，即使它已由 `users` 匯出。

```python
class ProfileService:
    def __init__(self, directory: UserDirectory) -> None:
        self._directory = directory

    def display_name(self, user_id: int) -> str:
        return self._directory.find_name(user_id) or "匿名使用者"


class ProfilesProvider(Provider):
    profile_service = provide(ProfileService, scope=Scope.APP)


profiles = Module(
    name="profiles",
    providers=(ProfilesProvider(),),
    exports=(ProfileService,),
    requires=(UserDirectory,),
)
application_with_profiles = Application(modules=(*application.modules, profiles))
```

未匯出的服務可供同模組的 providers 使用，但不會透過一般型別解析出現在其他模組或預設 component。這是一般 DI 查找的邊界，不是安全沙箱：若呼叫端明確指定 Dishka component，FastAPI-Fin 不會封鎖這種直接存取。HTTP 層的 `Inject[T]` 則使用預設 component，應只注入已匯出的服務契約。

## 宣告與組裝錯誤

不合法的模組宣告會拋出 `DefinitionError`；重複的模組名稱或匯出契約會在建立 `Application` 時拋出 `AssemblyError`。容器組裝時才檢查 `requires` 是否由其他模組匯出或由宿主的 context 提供，並驗證 Dishka 依賴圖。因此，缺少 provider、跨模組依賴未匯入，以及循環依賴等錯誤，可在處理請求前發現。

需要由宿主傳入的值，應由模組在 `requires` 中宣告，並由[容器作用域](scopes.md)提供，不要在模組的 provider 使用 `from_context`。
