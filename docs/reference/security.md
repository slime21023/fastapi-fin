# Security and JWT

The security API has three layers:

1. `TokenAuthenticator`: the contract for obtaining a principal from a bearer token. `JwtIssuer` / `JwtVerifier` issue and verify JWTs.
2. `AuthenticatedPrincipal` / `PrincipalPolicy`: hold the identity and claims, and describe scope and role authorization rules.
3. `FastAPISecurity`: connects authentication to FastAPI `Security` through `Inject[TokenAuthenticator]`.

The first two layers are exported by `fastapi_fin.security`; `FastAPISecurity` is exported by `fastapi_fin.adapters`. These public names can also be imported from `fastapi_fin`.

JWT support uses an optional dependency:

```console
pip install "fastapi-fin[security]"
```

If `PyJWT` is not installed, the first use of an issuer or verifier raises `SecurityDependencyError`.

## `TokenAuthenticator`

```python
class TokenAuthenticator(Protocol):
    def authenticate(
        self, token: str
    ) -> AuthenticatedPrincipal | Awaitable[AuthenticatedPrincipal]: ...
```

`token` is the credential without the `Bearer` prefix. The synchronous `JwtVerifier` already satisfies this contract and does not need to subclass it. Custom implementations can also return an awaitable; an expected credential rejection should raise `AuthenticationError` or a subclass.

## `AuthenticatedPrincipal`

```python
@frozen
class AuthenticatedPrincipal:
    subject: str
    issuer: str
    audience: tuple[str, ...]
    scopes: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    token_id: str | None = None
    token_type: str | None = None
    claims: Mapping[str, object] = {}
```

On construction, identity text is trimmed and validated, scopes, roles and audience are normalized to tuples, and
mappings/lists/tuples in claims are frozen recursively. A principal cannot be modified after it is created.

```python
principal.has_scope(scope: str) -> bool
principal.has_role(role: str) -> bool
```

`has_scope()` and `has_role()` are exact membership checks; they do not apply wildcards, hierarchy
or role inheritance. For compound rules, use `PrincipalPolicy` or an application service.

## `JwtKeySet`

```python
@frozen(kw_only=True)
class JwtKeySet:
    keys: Mapping[str, object]

    def __call__(self, header: Mapping[str, object]) -> object: ...
```

`JwtKeySet` is a local trusted key resolver:

- Key IDs must be non-empty strings.
- The key mapping must be non-empty and is copied into a read-only mapping; key IDs must not collide after leading and trailing whitespace is stripped.
- A missing, invalid or unknown `kid` raises `InvalidTokenError`.
- It never makes network requests based on a URL, issuer or other value in the token header.

```python
key_set = JwtKeySet(
    keys={
        "previous": previous_public_key,
        "current": current_public_key,
    },
)
```

A typical key rotation sequence is: add the new public key to the verifier first, then have the issuer use the new
`key_id`, and finally remove the old key once no unexpired token needs it.

`type JwtKeyResolver = Callable[[Mapping[str, object]], object]`. A custom resolver receives the unverified JWT header; use it only to select an already trusted key, never as a basis for identity or trust.

## `JwtVerifier`

```python
@frozen(kw_only=True)
class JwtVerifier:
    key: object | None = None
    key_resolver: JwtKeyResolver | None = None
    algorithms: tuple[str, ...]
    issuer: str
    audience: str | tuple[str, ...]
    required_claims: tuple[str, ...] = ("exp", "iat", "iss", "sub", "aud")
    expected_type: str | None = "at+jwt"
    require_jti: bool = True
    leeway: float = 0
    scope_claim: str = "scope"
    roles_claim: str = "roles"
```

Requirements at construction:

- Exactly one of `key` and `key_resolver` must be provided; providing both or neither is an error.
- `algorithms` must be an explicit, non-empty allowlist.
- The algorithm `none` is never accepted.
- `issuer`, `audience` and claim names must be valid.
- When `require_jti=True`, `jti` is added to the required claims automatically.

```python
def authenticate(self, token: str) -> AuthenticatedPrincipal: ...
```

Verification proceeds as follows:

1. Read the unverified header, using it only to check `alg` and `typ` and to select a trusted key.
2. Verify the signature using the configured algorithm allowlist.
3. Verify the issuer, audience, time claims and required claims as configured.
4. Normalize the claims into an immutable `AuthenticatedPrincipal`. `token_type` comes from the configured `expected_type`; if it is `None`, the header `typ` is not checked and the principal's `token_type` is also `None`.

An untrusted algorithm or token type, an invalid signature, or a PyJWT validation failure is reported as `InvalidTokenError`; invalid principal fields also raise `InvalidTokenError`. Failure to load PyJWT raises `SecurityDependencyError`, which is not an authentication rejection.

## `JwtIssuer`

```python
@frozen(kw_only=True)
class JwtIssuer:
    key: object
    algorithm: str
    issuer: str
    audience: str | tuple[str, ...]
    lifetime: timedelta = timedelta(minutes=15)
    token_type: str = "at+jwt"
    key_id: str | None = None
    scope_claim: str = "scope"
    roles_claim: str = "roles"
```

```python
def issue(
    self,
    subject: str,
    *,
    scopes: Iterable[str] = (),
    roles: Iterable[str] = (),
    token_id: str | None = None,
    additional_claims: Mapping[str, object] | None = None,
    now: datetime | None = None,
) -> str: ...
```

The issuer generates automatically:

- `iss`: the issuer
- `sub`: the subject
- `aud`: the audience
- `iat`: the issued time
- `exp`: `iat + lifetime`
- `jti`: the given token ID or a random UUID
- header `typ`: `token_type`
- header `kid`: added when `key_id` is set

Non-empty `scopes` are written as a space-separated string; non-empty `roles` are written as a list. `additional_claims` must not override `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, the configured scope/role claim names or `kid`.

```python
issuer = JwtIssuer(
    key=private_key,
    algorithm="RS256",
    issuer="https://identity.example",
    audience="task-api",
    lifetime=timedelta(minutes=10),
    key_id="current",
)

token = issuer.issue(
    "user-1",
    scopes=("tasks:read",),
    roles=("operator",),
)
```

A JWT carries signed claims, not an encrypted payload; do not put passwords, secrets or any data that
the bearer token holder should not read into claims.

## `PrincipalPolicy`

```python
@frozen
class PrincipalPolicy:
    scopes: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    all_roles: bool = True
    name: str = "principal-policy"
```

```python
policy.allows(principal: AuthenticatedPrincipal) -> bool
policy.enforce(principal: AuthenticatedPrincipal) -> None
```

- `name` must be non-empty after leading and trailing whitespace is stripped; otherwise `DefinitionError` is raised.
- All `scopes` must be present.
- When `all_roles=True`, all `roles` must be present.
- When `all_roles=False`, any one of `roles` is enough; empty roles add no restriction.
- `allows()` returns a bool.
- `enforce()` raises `InsufficientScopeError` when a scope is missing, and its `required_scopes` here contains only the missing scopes; any other rejection raises `AuthorizationError`.

```python
def require_scopes(*scopes: str, name: str = "required-scopes") -> PrincipalPolicy: ...


def require_roles(
    *roles: str,
    all_roles: bool = True,
    name: str = "required-roles",
) -> PrincipalPolicy: ...
```

## `FastAPISecurity`

```python
FastAPISecurity(
    *,
    token_url: str | None = None,
    scopes: Mapping[str, str] | None = None,
    scheme_name: str | None = None,
    description: str | None = None,
)
```

When `token_url` is set, FastAPI `OAuth2PasswordBearer` is used and `scopes` is published to OpenAPI; without `token_url`, `HTTPBearer` is used. Both use `auto_error=False`, so the adapter handles the authentication and authorization responses. The adapter does not create a token endpoint.

The constructor does not accept an authenticator. The application must provide `TokenAuthenticator` through a Dishka provider, declare `exports=(TokenAuthenticator,)` in its `Module`, and include that module in the `FinComposition` passed to `FastAPIIntegration`. If `token_url` is not `None`, it must be non-blank text; if `scopes` is provided, it must be a mapping of non-blank scope names to non-blank descriptions. Invalid settings raise `AdapterError`. For an example, see the [security guide](../guide/security.md).

`scheme` is the optional FastAPI bearer scheme; `scopes` is a read-only mapping of scope descriptions copied at construction; `current_principal` is the dependency callable that resolves the bearer credential, injects the authenticator and checks FastAPI `SecurityScopes`. Regular routes use the two marker methods below.

### `principal_marker()`

```python
def principal_marker(
    self,
    *,
    scopes: tuple[str, ...] = (),
) -> SecurityMarker: ...
```

Returns a FastAPI `Security` marker that can be placed in `Annotated` metadata:

```python
@router.get("/tasks")
def list_tasks(
    principal: Annotated[
        AuthenticatedPrincipal,
        security.principal_marker(scopes=("tasks:read",)),
    ],
) -> list[TaskView]:
    return service.list_for(principal.subject)
```

Required scope names must be non-empty strings. If `FastAPISecurity(scopes=...)` is given a non-empty mapping, every required scope must be listed in it; otherwise creating the marker raises `AdapterError`. An empty mapping performs no name check.

### `require()`

```python
def require(self, policy: PrincipalPolicy) -> DependsMarker: ...
```

Returns a FastAPI `Depends` marker. It obtains the principal through `Security` using the policy's scopes, then runs `policy.enforce()` and returns the same principal. Passing a value that is not a `PrincipalPolicy`, or scopes that do not match the configuration, raises `AdapterError`:

```python
admin = require_roles("admin")


@router.get("/admin")
def admin_area(
    principal: Annotated[AuthenticatedPrincipal, security.require(admin)],
) -> dict[str, str]:
    return {"subject": principal.subject}
```

### HTTP semantics

| Case | Status | Header |
| --- | --- | --- |
| Missing bearer token, authentication rejected, or the return value is not an `AuthenticatedPrincipal` | `401` | `WWW-Authenticate: Bearer` |
| Valid token but insufficient scope | `403` | `WWW-Authenticate: Bearer error="insufficient_scope", scope="..."` |
| Valid token but rejected by a role or policy | `403` | No special bearer header |

The `scope` returned by the HTTP scope check lists all scopes the dependency requires, not only the missing ones. If a policy itself raises `InsufficientScopeError`, the adapter uses the `required_scopes` in the exception. The authentication adapter does not convert arbitrary exceptions to `401`; see [errors](errors.md).

## Token lifecycle boundaries

The following features are deliberately excluded from the issuer/verifier:

- Password storage and login databases.
- Refresh token rotation.
- Logout and immediate revocation stores.
- External OIDC discovery or JWKS HTTP fetching.

These features should be handled by the application, an identity service or an external IdP. The application is responsible for configuring trusted keys for the verifier, or for providing another `TokenAuthenticator` implementation.
