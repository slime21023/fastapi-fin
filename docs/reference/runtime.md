# Runtime

Runtime classes hold mutable execution state for an already assembled immutable application
model. They are lower-level APIs: normal FastAPI applications should let
`FastAPIAdapter.create_app()` create and close them.

## Runtime state model

```text
ApplicationDefinition
        ↓ assemble()
ApplicationModel
        ↓
ApplicationRuntime
        ├─ application-scoped provider values
        └─ RequestContext per request
             └─ request-scoped provider values
```

`ApplicationRuntime` is not safe to share between separate application instances. A single
runtime can serve concurrent requests; application provider creation is protected by a per-token
async lock.

## `RequestContext`

```python
@define(slots=True)
class RequestContext:
    values: dict[ServiceToken, object] = field(factory=dict)
```

### Constructor and properties

```python
RequestContext()
context.values -> dict[ServiceToken, object]
context.closed -> bool
```

`values` is the request-scoped cache. It is normally managed by the runtime and should not be
edited by endpoint code.

### `ensure_open()`

```python
def ensure_open(self) -> None: ...
```

Raises `RuntimeClosedError` if the context has already been closed.

### `track()`

```python
def track(
    self,
    value: object,
    disposer: Callable[[object], object | Awaitable[object]] | None,
) -> None: ...
```

Registers a disposer for a request-owned value. Disposers run in reverse registration order
during `close()`. Calling `track()` on a closed context raises `RuntimeClosedError`.

### `close()` and async context manager

```python
async def close(self) -> None: ...


async with context:
    ...
```

`close()` is idempotent. It marks the context closed, executes all disposers, then clears owned
values. If one or more disposers fail, all disposers are still attempted and an
`ExceptionGroup("request resource cleanup failed", ...)` is raised.

## `ApplicationRuntime`

```python
@define(slots=True, eq=False, repr=False)
class ApplicationRuntime:
    model: ApplicationModel
```

Create it with the result of `assemble()`:

```python
model = assemble(definition)
runtime = ApplicationRuntime(model)
```

### State properties

```python
runtime.started -> bool
runtime.closed -> bool
```

`started` is true only after `start()` succeeds and before `stop()` begins. Once `stop()` has
been called, the runtime cannot be restarted or used to create request contexts.

### `start()`

```python
async def start(self) -> None: ...
```

Starts the runtime and resolves all `eager=True` application providers in assembled provider
order. Repeated calls after a successful start are no-ops.

If eager provider creation fails, `start()` calls `stop()` to clean up resources created so far,
then propagates the failure.

### `new_request()`

```python
def new_request(self) -> RequestContext: ...
```

Creates a request context only while the runtime is started. Calling it before `start()` or after
`stop()` raises `RuntimeClosedError`.

### `resolve()`

```python
async def resolve(
    self,
    token: ServiceToken,
    context: RequestContext | None = None,
) -> object: ...
```

Resolution rules:

| Provider | Required context | Caching |
| --- | --- | --- |
| `Scope.APPLICATION` | no | one value per runtime |
| `Scope.REQUEST` | yes | one value per request context |

The runtime resolves declared dependencies before calling the factory. A factory can be sync or
async. Factory failures are wrapped in `ResolutionError`; existing `ResolutionError` and
`RuntimeClosedError` values are not double-wrapped.

```python
await runtime.start()
context = runtime.new_request()
try:
    repository = await runtime.resolve(UserRepository, context)
finally:
    await context.close()
    await runtime.stop()
```

In a real application, `stop()` belongs to application shutdown rather than request cleanup.

### `stop()`

```python
async def stop(self) -> None: ...
```

Closes application-scoped resources in reverse creation order, clears provider values and locks,
and marks the runtime closed. It is idempotent. Cleanup failures are collected into an
`ExceptionGroup("application resource cleanup failed", ...)` after every disposer has been
attempted.

## Runtime ownership rules

- `FastAPIAdapter.create_app()` owns runtime startup and shutdown.
- A request dependency owns `RequestContext.close()` after the endpoint finishes.
- `FastAPIAdapter.mount()` does not create runtime and therefore rejects providers, injection and
  lifecycle hooks.
- Never keep a `RequestContext` or request-scoped provider in application-global state.
