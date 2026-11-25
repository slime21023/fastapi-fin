# Scopes and cleanup

Use Dishka's `Scope` directly. `Scope.APP` instances are shared within the same root container; `Scope.REQUEST` instances are shared within the same child container and are not shared across child containers. A longer-lived service cannot depend on a shorter-lived one; for example, an APP factory cannot depend on a REQUEST database session.

The FastAPI integration holds the root container in the lifespan and enters the REQUEST scope when an HTTP request needs injection.
When you use Dishka generator or async generator factories, created resources are cleaned up when their scope exits.
In a REQUEST factory, `exc = yield resource` receives the exception the child container ended with, so you can decide whether to commit or roll back a transaction;
use `try/finally` to make sure resources are released. FastAPI-Fin uses `AsyncContainer`; synchronous factories also work,
but they run directly on the event loop, so do not perform blocking I/O in them.

A `Scope.APP` factory runs when it is first resolved, not at lifespan startup. To create resources before serving starts, see "Create APP resources at startup" in [Running with Uvicorn](deployment.md).

## Using the container without HTTP

`open_container()` creates the root container and closes it when the `async with` block exits. A worker or script can open a single root container and then open a child container for each job. If you call `build_container()` directly, the caller must `await container.close()`.

Below is a runnable worker example. `context={Job: Scope.REQUEST}` only declares in which scope the host will provide `Job`; the actual value is passed when entering that child scope. The `context` parameter of these two assembly functions is not a dictionary of values, and it provides no way to pass values into the root APP scope.

```python
import asyncio
from dataclasses import dataclass

from dishka import Provider, Scope, provide

from fastapi_fin import FinComposition, Module, open_container


@dataclass(frozen=True)
class Job:
    filename: str


class ReportName:
    def __init__(self, job: Job) -> None:
        self.filename = job.filename


class ReportsProvider(Provider):
    report_name = provide(ReportName, scope=Scope.REQUEST)


composition = FinComposition(
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
    async with open_container(composition, context={Job: Scope.REQUEST}) as root:
        for filename in ("daily.csv", "weekly.csv"):
            async with root(scope=Scope.REQUEST, context={Job: Job(filename)}) as job:
                report = await job.get(ReportName)
                assert report.filename == filename


if __name__ == "__main__":
    asyncio.run(main())
```

The root container can directly resolve exported contracts in the APP scope; a REQUEST-scoped service such as `ReportName` must be obtained from a child container. Do not keep short-lived resources beyond the end of their scope. For a runnable transaction cleanup example, see the [examples index](../examples/index.md).
