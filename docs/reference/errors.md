# Errors

## Exception hierarchy and import locations

```text
FastAPIFinError
├─ DefinitionError
├─ AssemblyError
├─ AdapterError
└─ SecurityError
   ├─ SecurityDependencyError
   ├─ AuthenticationError
   │  ├─ MissingCredentialsError
   │  └─ InvalidTokenError
   └─ AuthorizationError
      └─ InsufficientScopeError
```

`fastapi_fin.errors` exports only `FastAPIFinError`, `DefinitionError`, `AssemblyError`, and `AdapterError`; `SecurityError` and its subclasses are exported by `fastapi_fin.security`. All of these names can also be imported from `fastapi_fin`.

## Declaration, assembly, and integration

| Exception | When it is raised and who handles it |
| --- | --- |
| `DefinitionError` | A `Module` or `FinProxy` field has an invalid format, e.g. an empty module name, a duplicate contract entry, or a provider that sets its own component; also used for an invalid context declaration in `build_container()` and for invalid JWT or policy settings. Fix the input. |
| `AssemblyError` | `FinProxy` detects a duplicate module name, a duplicate export, or an override target that is not exported; `build_container()` detects an unsatisfied `requires`, a conflict between context and an export, or receives a value that is not a `FinProxy`. Specific Dishka graph exceptions are wrapped as `AssemblyError`, with the original error kept in `__cause__`. The FastAPI lifespan also raises this error when it detects a route injecting an unexported contract. Fix the assembly and dependency declarations. |
| `AdapterError` | `Inject[T]` receives a string, `None`, or unhashable contract key; the integration object or lifespan argument has the wrong type; a WebSocket using `Inject` is detected at startup; a request has no available container; or the security adapter is configured invalidly. Fix the integration; this is not an expected HTTP authentication failure. |

Exceptions raised while resolving from the container or running provider factories are not wrapped by FastAPI-Fin, and are not converted into a fixed-format `500` response. When you operate the container directly, the caller handles them; in an HTTP request they follow FastAPI's exception handling. Container and scope cleanup errors are reported by Dishka.

## Security exceptions

| Exception | Meaning |
| --- | --- |
| `SecurityDependencyError` | PyJWT cannot be loaded when using JWT; install `fastapi-fin[security]`. This is a deployment problem, not an invalid token. |
| `AuthenticationError` | The credentials fail authentication. A custom `TokenAuthenticator` can use this exception to signal an expected authentication failure. |
| `MissingCredentialsError` | No credentials were provided; for authentication code that does not depend on FastAPI. |
| `InvalidTokenError` | The token format, signature, or trust conditions do not match, or a principal field is invalid. |
| `AuthorizationError` | The authenticated principal does not satisfy the authorization policy. |
| `InsufficientScopeError` | The scopes required for authorization are insufficient; `required_scopes` is the scope tuple passed when the exception is created. `PrincipalPolicy.enforce()` passes the missing items. |

`FastAPISecurity` converts a missing bearer credential, an `AuthenticationError` raised by `authenticate()`, or an authenticator that does not return an `AuthenticatedPrincipal` into a `401`. When the adapter detects insufficient scope, or when `require()` runs a policy that raises `InsufficientScopeError`, it returns a `403` containing `insufficient_scope`; any other `AuthorizationError` raised by a policy becomes a `403`. These mappings occur only within that adapter's authentication and authorization flow; it is not a global exception handler. See the [security reference](security.md) for details.
