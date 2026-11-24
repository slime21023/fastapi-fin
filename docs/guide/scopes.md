# 作用域與資源清理

直接使用 Dishka 的 `Scope`。`Scope.APP` 實例在同一根容器內共用；`Scope.REQUEST` 實例在同一子容器內共用，不會跨子容器共用。較長生命週期的服務不能依賴較短生命週期的服務，例如 APP 工廠不能依賴 REQUEST 的資料庫工作階段。

FastAPI 整合在 lifespan 內持有根容器，並在 HTTP 請求需要注入時進入 REQUEST scope。
使用 Dishka 的 generator 或 async generator 工廠時，已建立的資源會在離開所屬作用域時清理。
在 REQUEST 工廠中可用 `exc = yield resource` 接收子容器結束時收到的例外，據以決定提交或回復交易；
用 `try/finally` 確保釋放資源。FastAPI-Fin 使用 `AsyncContainer`，同步工廠也可用，
但會直接在 event loop 上執行，請勿在其中進行阻塞式 I/O。

`Scope.APP` 的工廠在第一次被解析時才執行，不是在 lifespan 啟動時；若要在開始服務前建立資源，見[使用 Uvicorn 啟動](deployment.md)中的「在啟動時建立 APP 資源」。

## 不經 HTTP 使用容器

`open_container()` 建立根容器，並在離開 `async with` 時關閉。worker 或指令稿可以只開一個根容器，再為每件工作開一個子容器。若直接呼叫 `build_container()`，呼叫端必須負責 `await container.close()`。

以下是可直接執行的 worker 範例。`context={Job: Scope.REQUEST}` 只宣告宿主將在哪個作用域提供 `Job`；實際值在進入該子作用域時傳入。這兩個組裝函式的 `context` 參數不是值的字典，也不提供把值傳入根 APP scope 的入口。

```python
import asyncio
from dataclasses import dataclass

from dishka import Provider, Scope, provide

from fastapi_fin import Application, Module, open_container


@dataclass(frozen=True)
class Job:
    filename: str


class ReportName:
    def __init__(self, job: Job) -> None:
        self.filename = job.filename


class ReportsProvider(Provider):
    report_name = provide(ReportName, scope=Scope.REQUEST)


application = Application(
    modules=(
        Module(
            name="reports",
            providers=(ReportsProvider(),),
            exports=(ReportName,),
            requires=(Job,),
        ),
    ),
)


async def main() -> None:
    async with open_container(application, context={Job: Scope.REQUEST}) as root:
        for filename in ("daily.csv", "weekly.csv"):
            async with root(scope=Scope.REQUEST, context={Job: Job(filename)}) as job:
                report = await job.get(ReportName)
                assert report.filename == filename


if __name__ == "__main__":
    asyncio.run(main())
```

根容器可直接解析 APP 作用域的匯出契約；像 `ReportName` 這種 REQUEST 作用域的服務必須從子容器取得。不要把短生命週期的資源保留到其作用域結束之後。交易清理的可執行範例見[範例索引](../examples/index.md)。
