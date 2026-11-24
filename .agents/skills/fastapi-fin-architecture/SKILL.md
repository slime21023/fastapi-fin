---
name: fastapi-fin-architecture
description: Enforce FastAPI-Fin's service contract, Dishka composition, security, and native FastAPI adapter boundaries.
---

# FastAPI-Fin Architecture

FastAPI-Fin composes service contracts with Dishka and uses FastAPI as the HTTP host. Follow README.md, docs/guide/concepts.md, and CONTRIBUTING.md.

- Put immutable declarations and input validation in `fastapi_fin/modules.py`. Use explicit exports and requires rather than coupling consumers to a provider or its component name.
- Assemble modules in `fastapi_fin/container.py`. Use Dishka for graph validation, scopes, caching and finalization. Do not implement a second resolution runtime.
- Keep JWT, identity, policy and `TokenAuthenticator` framework-independent in `fastapi_fin/security/`.
- Only `fastapi_fin/adapters/` may import FastAPI. Use native dependencies and lifespan; do not use `dishka.integrations`, patch routes, install mandatory middleware, or wrap endpoint signatures.
- Validate contract declarations before serving requests. Keep factory exceptions visible to host handlers; chain graph construction errors as the cause of `AssemblyError`.
- Keep production and test compositions independent; use overrides on a new application instead of mutating providers after declaration.

Verify changed behavior with focused tests, then run Ruff and ty before delivery.

