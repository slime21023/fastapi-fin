# Security and JWT

FastAPI-Fin keeps authentication and authorization separate. JWT only issues and verifies tokens;
scopes, roles and resource policies are handled by independent authorization policies.

JWT support is an optional dependency:

```console
pip install "fastapi-fin[security]"
```

## Creating a JWT issuer and verifier

```python
from datetime import timedelta

from fastapi_fin.security import JwtIssuer, JwtVerifier

issuer = JwtIssuer(
    key=secret_key,
    algorithm="HS256",
    issuer="https://issuer.example",
    audience="task-api",
    lifetime=timedelta(minutes=15),
)

verifier = JwtVerifier(
    key=secret_key,
    algorithms=("HS256",),
    issuer="https://issuer.example",
    audience="task-api",
)

token = issuer.issue("user-1", scopes=("tasks:read",), roles=("admin",))
principal = verifier.authenticate(token)
```

By default, `JwtVerifier` validates the signature and the algorithm allowlist, `iss`, `aud`, the time claims `exp` and `iat`, the identity claim `sub`, the token ID `jti`, and the header `typ` (default `at+jwt`). Symmetric algorithms use the same key for issuing and verifying. Do not take the allowed algorithms from the token header, and do not treat a JWT as encrypted data.

If several services only need to verify tokens and must not hold the signing private key, use asymmetric signing: the issuer holds the private key and verifiers hold the trusted public keys. For local key rotation, use the immutable `JwtKeySet`:

```python
from fastapi_fin.security import JwtKeySet, JwtVerifier

keys = JwtKeySet(
    keys={
        "old": old_public_key,
        "current": current_public_key,
    }
)

verifier = JwtVerifier(
    key_resolver=keys,
    algorithms=("RS256",),
    issuer="https://issuer.example",
    audience="task-api",
)
```

`kid` is looked up only in the configured trusted key set; no external resource is fetched
from a URL in the token.
If you use this RS256 verifier, the issuer must also use `RS256` and create its `JwtIssuer` with the matching private key and `key_id`; this verifier cannot verify the tokens issued with HS256 above.

## Connecting the authentication contract to FastAPI

`JwtVerifier` already satisfies the `TokenAuthenticator` contract. Provide that contract with a Dishka provider and export it from a module. `FastAPISecurity` does not accept a verifier directly; it resolves it through `Inject[TokenAuthenticator]`. The example below reuses the `verifier` chosen in the previous section:

```python
from typing import Annotated

from dishka import Provider, Scope, provide
from fastapi import FastAPI

from fastapi_fin import Application, FastAPIIntegration, FastAPISecurity, Module
from fastapi_fin.security import AuthenticatedPrincipal, TokenAuthenticator, require_roles


class AuthProvider(Provider):
    @provide(scope=Scope.APP)
    def authenticator(self) -> TokenAuthenticator:
        return verifier


auth = Module(
    name="auth",
    providers=(AuthProvider(),),
    exports=(TokenAuthenticator,),
)
integration = FastAPIIntegration(Application(modules=(auth,)))
app = FastAPI(lifespan=integration.lifespan)
security = FastAPISecurity(
    token_url="/token",
    scopes={"tasks:read": "Read tasks"},
)


@app.get("/tasks")
async def list_tasks(
    principal: Annotated[
        AuthenticatedPrincipal,
        security.principal_marker(scopes=("tasks:read",)),
    ],
) -> dict[str, str]:
    return {"subject": principal.subject}


@app.get("/admin")
async def admin_area(
    principal: Annotated[AuthenticatedPrincipal, security.require(require_roles("admin"))],
) -> dict[str, str]:
    return {"subject": principal.subject}
```

`principal_marker()` uses the FastAPI `Security` dependency. With `token_url`, it uses the OAuth2 password bearer scheme and shows the declared scopes in OpenAPI. `token_url` points to a token endpoint implemented by the application or an identity service; the adapter does not create that route. Without `token_url`, it uses the HTTP bearer scheme.

`security.require(policy)` first authenticates the bearer token, then checks the `PrincipalPolicy`. In the example, `/admin` requires the authenticated principal to have the `admin` role, and `/tasks` requires the `tasks:read` scope. For resource-level authorization, such as allowing users to read only the tasks they created, implement the check in application queries or services based on the principal.

- Missing or invalid token: `401` with `WWW-Authenticate: Bearer`.
- Valid token but insufficient scope: `403` with `insufficient_scope` information in `WWW-Authenticate`.
- Scope check passes but the role does not match: `403`.

Another provider can supply a synchronous or asynchronous `TokenAuthenticator` instead. An expected credential rejection should raise `AuthenticationError` (e.g. `InvalidTokenError`) rather than swallowing service errors. If `TokenAuthenticator` is not exported, the lifespan raises `AssemblyError` as long as startup validation finds the authentication dependency on a route.

## Per-resource access rules

Name scopes per resource as `<resource>:<action>` (for example `docs:read` and `docs:write`) and declare them in `FastAPISecurity(scopes=...)`; a route that uses an undeclared scope raises `AdapterError` when it is defined. `security.require(policy)` returns a marker that works as an endpoint parameter and in `APIRouter(dependencies=[...])`. A router-level policy and a route-level policy both apply, so a router can require `docs:read` while one route also requires `docs:write`. Scopes are compared as exact strings; wildcards such as `docs:*` are not expanded.

Rules that depend on data, such as "only the owner may edit this document", cannot be decided from the token. Put them in an exported service contract that receives the `AuthenticatedPrincipal`, and replace that service in tests with `Application.with_overrides()`. See [`07_resource_authorization.py`](https://github.com/slime21023/fastapi-fin/blob/main/examples/07_resource_authorization.py).

Every `FastAPISecurity` instance resolves the same exported `TokenAuthenticator` contract, so one application trusts one authenticator. To accept tokens from several issuers, export a single authenticator that dispatches to the matching `JwtVerifier`.

## Token lifecycle boundaries

The JWT issuer and verifier currently do not handle:

- user password storage and login databases
- refresh token rotation
- logout or immediate token revocation
- external OIDC provider discovery

These should be implemented by an application provider or an external identity service. Short-lived
access tokens are recommended; if you need immediate revocation, add a revocation store or use
opaque refresh/session tokens instead of
assuming a JWT can log itself out.

[`08_revocation_and_rate_limits.py`](https://github.com/slime21023/fastapi-fin/blob/main/examples/08_revocation_and_rate_limits.py) wraps `JwtVerifier` in an authenticator that rejects revoked JWT IDs with `InvalidTokenError`, which becomes a `401`, after the signature is verified. Errors raised by the store itself are not authentication errors, so they propagate as a `500` instead of letting the request through. Keep each revoked ID until the token's `exp`. The same example rate-limits a route with a dependency that returns `429` with `Retry-After`. In-memory stores exist once per worker, so use a shared store such as Redis with `--workers N`. Per-IP limits on login attempts belong in a reverse proxy or middleware, because a `TokenAuthenticator` receives only the token.

For a runnable example, see [`06_security_jwt.py`](https://github.com/slime21023/fastapi-fin/blob/main/examples/06_security_jwt.py); for the full signing, authentication and authorization API, see the [security reference](../reference/security.md).
