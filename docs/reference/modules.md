# Modules and container

All of the following APIs can be imported from `fastapi_fin` and do not depend on FastAPI. Providers, scopes, resolution, and resource lifecycle use Dishka's API.

## `Module`

```python
Module(
    name: str,
    providers: tuple[Provider, ...] = (),
    exports: tuple[object, ...] = (),
    requires: tuple[object, ...] = (),
)
```

- `name` must be non-empty after leading and trailing whitespace is stripped, and is used as the Dishka component name. The empty string is reserved for Dishka's default component.
- `providers` are Dishka `Provider` instances. Do not set a non-default component on a provider or use `from_context` yourself: the module assigns the former, and the container declares the latter.
- `exports` lists the service contracts that other modules and callers can obtain; `requires` lists the contracts to obtain from other modules or from the supplied context. A contract here is a type hint usable as a Dishka key (e.g. a `Protocol`, an ABC, or a concrete type), not an OpenAPI schema.
- A contract key must not be a string or `None`, and must be hashable. A field cannot contain duplicate keys, and a module cannot both export and require the same key.

Collection inputs are normalized to tuples; a declaration cannot be reassigned, but it is not a deep copy of the provider instances. Invalid fields raise `DefinitionError`.

## `FinComposition`

```python
FinComposition(modules: tuple[Module, ...] = (), overrides: Mapping[object, object] = {})
```

`modules` is normalized to a tuple and accepts only `Module` instances. `exports` is a read-only `Mapping[object, str]` that maps each contract to the name of the module that exports it. `overrides` is a read-only shallow snapshot that maps each contract to its replacement instance.

Duplicate module names, a contract exported by more than one module, or an override of a contract that is not exported raise `AssemblyError` when the `FinComposition` is created. Whether `requires` is satisfied is checked only when the container is built, because context declarations are known only then.

### `with_overrides(overrides)`

Takes a `Mapping[object, object]` and returns a new `FinComposition`; the original is unchanged, and for the same key the new value wins. Replacement instances are available in the APP scope and take effect for the default component, the exporting module itself, and modules that import the contract through `requires`. The container uses the instance supplied by the caller and is not responsible for its cleanup; it does not call the original contract's factory to produce a fake.

## `build_container()` and `open_container()`

```python
build_container(composition, *, context={}) -> AsyncContainer
open_container(composition, *, context={})  # async context manager, yields AsyncContainer
```

`composition` must be a `FinComposition`. `context` is a `Mapping[object, BaseScope]` that maps a contract key to a Dishka `BaseScope`; it declares the type and scope of a value, not the value itself. For example, `context={Job: Scope.REQUEST}`, and then pass the value with `async with root(context={Job: job}, scope=Scope.REQUEST) as request:`. These two functions do not accept context values in the APP scope.

The default component can resolve exported contracts and declared context; each module resolves in its own component by default, and obtains the imported aliases created at assembly time through `requires`. The container does not create cross-component aliases for ordinary unexported dependencies; this is not access control and does not prevent code from reaching an object by explicitly naming a component through Dishka.

An invalid context declaration raises `DefinitionError`. An unsatisfied `requires`, a conflict between context and an exported key, or an input that is not a `FinComposition` raises `AssemblyError`. The build uses Dishka's strict validation; `InvalidGraphError` and `AliasedFactoryNotFoundError` are wrapped as `AssemblyError`, and other Dishka exceptions are not converted.

After `build_container()`, the caller is responsible for `await container.close()` on the root container; `async with open_container(...)` closes it automatically on exit. Child scopes are managed by the code that enters them. The container is asynchronous; synchronous factories still work but run directly on the event loop.

See the [module guide](../guide/modules.md), [lifecycle and scopes](../guide/scopes.md), and [Errors](errors.md).
