# FastAPI integration

`FastAPIIntegration`, `Inject`, `CONTAINER_STATE_KEY`, and `FastAPISecurity` can be imported from `fastapi_fin` or `fastapi_fin.adapters`. For the authentication and authorization APIs, see also the [security reference](security.md).

## `FastAPIIntegration(application)`

`application` must be an `Application`; otherwise `AdapterError` is raised. The integration object cannot be reassigned; the actual container is created when the lifespan starts.

### `lifespan(app)`

```python
integration = FastAPIIntegration(application)
app = FastAPI(lifespan=integration.lifespan)
```

This async context manager takes a `FastAPI` instance, creates a new Dishka container at startup, checks route injections, and yields a `dict[str, object]`. The integration object owns the root container and closes it when the lifespan exits. Passing any other type raises `AdapterError`.

`CONTAINER_STATE_KEY` has the value `"fastapi_fin_container"` and is the key of the root container in the lifespan state dictionary; it is not an `app.state` field. When you compose your own lifespan, keep this key and value so that ASGI passes it to `request.state`. For full usage, see the [FastAPI integration guide](../guide/fastapi.md).

### Startup validation scope

- Checks every `Inject` that FastAPI HTTP routes can recognize, including parameters, nested `Depends` or `Security`, and dependencies set on routes and routers. Detecting an unexported contract raises `AssemblyError`.
- WebSocket does not support `Inject`; detecting its use at startup raises `AdapterError`.
- Routes of mounted sub-apps are not traversed. Mounted HTTP routes can obtain the container from the host ASGI lifespan state, but the host does not validate their injections at startup.

## `Inject[T]`

Use `Inject[T]` in a parameter annotation, where `T` is an exported service contract. To a type checker the parameter type is `T`; at runtime it creates `Annotated[T, Depends(...)]`, FastAPI runs the dependency, and the object is obtained from the Dishka REQUEST scope. Injections within the same HTTP request share the same REQUEST scope. A string, `None`, or unhashable contract key raises `AdapterError`; so does failing to find an active root container at request time.

`Request` is a context declared by the integration as `Scope.REQUEST`, and the current request is supplied when the request scope is opened. A module that needs it in a provider can declare `requires=(Request,)`; an endpoint can use FastAPI's native `request: Request` directly instead of `Inject[Request]`.

The integration adds no middleware, does not rewrite the route class, and does not wrap endpoints. `Inject[T]` itself does not become an OpenAPI request parameter or request body; routing, validation, OpenAPI, and exception handling remain managed by FastAPI.
