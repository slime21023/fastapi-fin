from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest

from fastapi_fin.errors import DefinitionError
from fastapi_fin.security import (
    AuthenticatedPrincipal,
    AuthorizationError,
    InsufficientScopeError,
    InvalidTokenError,
    JwtIssuer,
    JwtKeySet,
    JwtVerifier,
    require_roles,
    require_scopes,
)

KEY = "k" * 32


def issuer() -> JwtIssuer:
    return JwtIssuer(
        key=KEY,
        algorithm="HS256",
        issuer="https://issuer.example",
        audience="api",
    )


def verifier(**kwargs: Any) -> JwtVerifier:
    return JwtVerifier(
        key=KEY,
        algorithms=("HS256",),
        issuer="https://issuer.example",
        audience="api",
        **kwargs,
    )


def test_jwt_issue_and_verify_builds_immutable_principal() -> None:
    token = issuer().issue("user-1", scopes=("users:read",), roles=("admin",))

    principal = verifier().authenticate(token)

    assert principal == AuthenticatedPrincipal(
        subject="user-1",
        issuer="https://issuer.example",
        audience=("api",),
        scopes=("users:read",),
        roles=("admin",),
        token_id=principal.token_id,
        token_type="at+jwt",
        claims=principal.claims,
    )
    assert principal.has_scope("users:read")
    assert principal.has_role("admin")
    with pytest.raises(AttributeError):
        setattr(principal, "subject", "other")  # noqa: B010


def test_verifier_rejects_wrong_algorithm_issuer_audience_and_type() -> None:
    token = issuer().issue("user-1")

    with pytest.raises(InvalidTokenError):
        JwtVerifier(
            key=KEY,
            algorithms=("RS256",),
            issuer="https://issuer.example",
            audience="api",
        ).authenticate(token)
    with pytest.raises(InvalidTokenError):
        JwtVerifier(
            key=KEY,
            algorithms=("HS256",),
            issuer="https://other.example",
            audience="api",
        ).authenticate(token)
    with pytest.raises(InvalidTokenError):
        JwtVerifier(
            key=KEY,
            algorithms=("HS256",),
            issuer="https://issuer.example",
            audience="other-api",
        ).authenticate(token)
    with pytest.raises(InvalidTokenError):
        JwtVerifier(
            key=KEY,
            algorithms=("HS256",),
            issuer="https://issuer.example",
            audience="api",
            expected_type="custom+jwt",
        ).authenticate(token)


def test_verifier_requires_jti_and_rejects_untrusted_key_id() -> None:
    now = datetime.now(UTC)
    claims = {
        "iss": "https://issuer.example",
        "sub": "user-1",
        "aud": "api",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    token = jwt.encode(claims, KEY, algorithm="HS256", headers={"typ": "at+jwt"})
    with pytest.raises(InvalidTokenError):
        verifier().authenticate(token)

    key_set = JwtKeySet(keys={"current": KEY})
    rotating_verifier = JwtVerifier(
        key_resolver=key_set,
        algorithms=("HS256",),
        issuer="https://issuer.example",
        audience="api",
    )
    rotating_issuer = JwtIssuer(
        key=KEY,
        algorithm="HS256",
        issuer="https://issuer.example",
        audience="api",
        key_id="current",
    )
    rotating_token = rotating_issuer.issue("user-1")
    assert rotating_verifier.authenticate(rotating_token).subject == "user-1"


def test_key_set_resolves_kid_and_policies_enforce_claims() -> None:
    key_set = JwtKeySet(keys={"current": KEY})
    assert key_set({"kid": "current"}) == KEY
    with pytest.raises(InvalidTokenError):
        key_set({"kid": "unknown"})

    principal = issuer_and_verify("user-1", scopes=("users:read",), roles=("admin",))
    require_scopes("users:read").enforce(principal)
    require_roles("admin").enforce(principal)
    with pytest.raises(InsufficientScopeError):
        require_scopes("users:write").enforce(principal)
    with pytest.raises(AuthorizationError, match="not allowed"):
        require_roles("operator").enforce(principal)


@pytest.mark.parametrize(
    ("factory", "value"),
    [
        (JwtVerifier, {"key": KEY, "algorithms": 123}),
        (JwtVerifier, {"key": KEY, "algorithms": ("HS256",), "audience": 123}),
        (JwtVerifier, {"key": KEY, "algorithms": ("HS256",), "issuer": 123}),
        (JwtVerifier, {"key": KEY, "algorithms": ("HS256",), "expected_type": 123}),
    ],
)
def test_verifier_rejects_malformed_definition_values(factory: Any, value: dict[str, Any]) -> None:
    kwargs = {
        "issuer": "https://issuer.example",
        "audience": "api",
        **value,
    }
    with pytest.raises(DefinitionError):
        factory(**kwargs)


def test_policy_rejects_malformed_requirements_at_definition_time() -> None:
    with pytest.raises(DefinitionError):
        require_scopes("")
    malformed_roles: Any = (123,)
    with pytest.raises(DefinitionError):
        require_roles(*malformed_roles)


def test_issuer_normalizes_claim_inputs_and_rejects_reserved_custom_names() -> None:
    token = issuer().issue("user-1", scopes="users:read", roles="admin", token_id="token-1")
    principal = verifier().authenticate(token)

    assert principal.scopes == ("users:read",)
    assert principal.roles == ("admin",)
    assert principal.token_id == "token-1"
    with pytest.raises(DefinitionError):
        issuer().issue("user-1", token_id="")
    with pytest.raises(DefinitionError):
        JwtIssuer(
            key=KEY,
            algorithm="HS256",
            issuer="https://issuer.example",
            audience="api",
            scope_claim="roles",
            roles_claim="roles",
        )


def issuer_and_verify(
    subject: str,
    *,
    scopes: tuple[str, ...] = (),
    roles: tuple[str, ...] = (),
) -> AuthenticatedPrincipal:
    return verifier().authenticate(issuer().issue(subject, scopes=scopes, roles=roles))
