# API reference

This section describes the public API of FastAPI-Fin, its assembly rules, and who is responsible for each error. If you are new, read [Getting started](../guide/getting-started.md) and [Core concepts](../guide/concepts.md) first.

| Page | Contents |
| --- | --- |
| [Modules and container](modules.md) | `Module`, `Application`, contract overrides, the Dishka container, and context |
| [FastAPI integration](fastapi.md) | `Inject[T]`, `FastAPIIntegration.lifespan`, and startup validation |
| [Security and JWT](security.md) | `TokenAuthenticator`, JWT, principal, policy, and `FastAPISecurity` |
| [Errors](errors.md) | Exception hierarchy, when each is raised, and who handles it |

## Import locations

- `fastapi_fin` exports the public API for modules, the container, adapters, and security.
- `fastapi_fin.adapters` provides the FastAPI integration; the root package loads these exports on demand.
- `fastapi_fin.security` provides the authentication contract, JWT, principal, policy, and security exceptions, none of which depend on FastAPI.
- `fastapi_fin.errors` defines the shared base, definition, assembly, and adapter exceptions.
- `Provider`, `provide`, `Scope`, and container operations come from `dishka`; use Dishka's API directly.

The core handles module contracts and container assembly; the adapter connects the container to FastAPI's lifespan and dependency mechanism. FastAPI remains responsible for route declarations, request and response validation, and OpenAPI.
