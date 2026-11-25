# Core concepts

FastAPI-Fin assembles services with Dishka so that modules cooperate through explicit contracts; the HTTP layer still uses native
FastAPI. A service contract describes how code obtains and uses an object. It is not an
OpenAPI contract describing HTTP requests and responses.

## From declaration to execution

```text
Module (providers, exports, requires)
    → FinComposition (combines modules and fakes)
    → build_container() (assembles and validates the Dishka dependency graph)
        ├─ FastAPIIntegration.lifespan → HTTP requests use Inject[T]
        └─ open_container() → workers, scripts, or tests use await container.get(T)
```

| Name | Responsibility |
| --- | --- |
| Contract | A `Protocol`, abstract base class, or other type hint Dishka can identify, used as the service key. |
| `Module` | Declares a set of Dishka providers and describes cross-module interfaces with `exports` and `requires`. |
| `FinComposition` | Combines modules, checks for module name and export conflicts, and records fakes for tests. |
| `AsyncContainer` | Dishka resolves dependencies, caches instances per scope, and cleans up resources. |
| `FastAPIIntegration` | Opens and closes the container in the lifespan, and lets `Inject` reach the child container of the current HTTP request through ASGI lifespan state. |

## Declarations and resource lifecycle

`Module` and `FinComposition` are frozen declarations; `with_overrides()` returns a new `FinComposition`
and does not modify the original declaration. Dishka `Provider` instances themselves are not deeply frozen, so finish registering them before assembly.
Only the assembled container holds the instances and cleanup state of each scope.

FastAPI-Fin does not add its own provider decorator, and it does not replace FastAPI's router, route classes, or endpoints.
Describe services with `Provider`, `@provide`, and `Scope`, and let `Inject[T]` bring services into routes through native `Depends`.
Without HTTP, manage the same dependency graph directly with `open_container()`.

Learn about [module boundaries](modules.md) and [scopes and cleanup](scopes.md).
