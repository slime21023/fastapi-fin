# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.9.1] - 2026-11-24

First public release.

### Added

- `Module` declares a module's public contracts and cross-module dependencies with `exports` and `requires`. `FinComposition` combines modules and validates duplicate module names and exports.
- `build_container()` and `open_container()` assemble a Dishka container. Each module is its own component and can only reach other modules through exported contracts. The dependency graph is validated with Dishka's strict validation; graph errors are raised as `AssemblyError` with the original exception kept as `__cause__`. Providers, `Scope`, and cleanup use Dishka's API directly.
- `FinComposition.with_overrides()` replaces an implementation per contract (an externally owned APP-scope instance). The override applies consistently to HTTP injection, other modules, and the exporting module itself.
- `FastAPIIntegration.lifespan` and `Inject[T]` inject services through native FastAPI `Depends`: no middleware, no route class changes, no endpoint wrapping. Routes are scanned at startup; injecting an unexported contract raises `AssemblyError`, and using `Inject` on a WebSocket route raises `AdapterError`.
- Security: the `TokenAuthenticator` contract, `JwtIssuer` / `JwtVerifier` / `JwtKeySet`, the immutable `AuthenticatedPrincipal` and `PrincipalPolicy` (`require_scopes` / `require_roles`), and `FastAPISecurity`, which integrates OAuth2 scopes and HTTP 401/403 semantics. JWT support is an optional install through `fastapi-fin[security]`.
- Uvicorn support: command-line single process and `--workers N`, resource cleanup after graceful shutdown, and refusing to start when a route injects an unexported contract. See the deployment guide.
- Guides, API reference, and runnable examples, including a complete Task API.

### Compatibility

- Python 3.12 and 3.13.
- Tested with FastAPI 0.115.11 (Starlette 0.46.2), 0.141.1 (Starlette 1.3.1), and 0.165.0; Dishka 1.10.1 (declared range `>=1.10.1,<2`); attrs 25.4.0 and the currently locked version; PyJWT 2.10.0 and the currently locked version.
- CI runs on Linux; Windows is verified locally.
