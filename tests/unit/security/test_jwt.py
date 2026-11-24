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
ISSUER_URL = "https://issuer.example"
AUDIENCE = "api"
ISSUER_DEFAULTS: dict[str, Any] = {
    "key": KEY,
    "algorithm": "HS256",
    "issuer": ISSUER_URL,
    "audience": AUDIENCE,
}
VERIFIER_DEFAULTS: dict[str, Any] = {
    "key": KEY,
    "algorithms": ("HS256",),
    "issuer": ISSUER_URL,
    "audience": AUDIENCE,
}


def issuer(**overrides: Any) -> JwtIssuer:
    return JwtIssuer(**ISSUER_DEFAULTS | overrides)


def verifier(**overrides: Any) -> JwtVerifier:
    return JwtVerifier(**VERIFIER_DEFAULTS | overrides)


def issuer_and_verify(
    subject: str,
    *,
    scopes: tuple[str, ...] = (),
    roles: tuple[str, ...] = (),
) -> AuthenticatedPrincipal:
    return verifier().authenticate(issuer().issue(subject, scopes=scopes, roles=roles))


def test_jwt_issue_and_verify_builds_immutable_principal() -> None:
    token = issuer().issue("user-1", scopes=("users:read",), roles=("admin",))

    principal = verifier().authenticate(token)

    assert principal == AuthenticatedPrincipal(
        subject="user-1",
        issuer=ISSUER_URL,
        audience=(AUDIENCE,),
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


@pytest.mark.parametrize(
    "overrides",
    [
        {"algorithms": ("RS256",)},
        {"issuer": "https://other.example"},
        {"audience": "other-api"},
        {"expected_type": "custom+jwt"},
    ],
    ids=["algorithm", "issuer", "audience", "type"],
)
def test_verifier_rejects_token_outside_trusted_settings(overrides: dict[str, Any]) -> None:
    token = issuer().issue("user-1")

    with pytest.raises(InvalidTokenError):
        verifier(**overrides).authenticate(token)


def test_verifier_requires_jti() -> None:
    now = datetime.now(UTC)
    claims = {
        "iss": ISSUER_URL,
        "sub": "user-1",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    token = jwt.encode(claims, KEY, algorithm="HS256", headers={"typ": "at+jwt"})

    with pytest.raises(InvalidTokenError):
        verifier().authenticate(token)


def test_verifier_resolves_rotating_keys_by_kid() -> None:
    rotating_verifier = verifier(key=None, key_resolver=JwtKeySet(keys={"current": KEY}))
    token = issuer(key_id="current").issue("user-1")

    assert rotating_verifier.authenticate(token).subject == "user-1"


def test_key_set_resolves_only_trusted_key_ids() -> None:
    key_set = JwtKeySet(keys={"current": KEY})

    assert key_set({"kid": "current"}) == KEY
    with pytest.raises(InvalidTokenError):
        key_set({"kid": "unknown"})


def test_policies_enforce_scopes_and_roles() -> None:
    principal = issuer_and_verify("user-1", scopes=("users:read",), roles=("admin",))

    require_scopes("users:read").enforce(principal)
    require_roles("admin").enforce(principal)
    with pytest.raises(InsufficientScopeError):
        require_scopes("users:write").enforce(principal)
    with pytest.raises(AuthorizationError, match="not allowed"):
        require_roles("operator").enforce(principal)


@pytest.mark.parametrize(
    "overrides",
    [
        {"algorithms": 123},
        {"audience": 123},
        {"issuer": 123},
        {"expected_type": 123},
    ],
    ids=["algorithms", "audience", "issuer", "expected_type"],
)
def test_verifier_rejects_malformed_definition_values(overrides: dict[str, Any]) -> None:
    with pytest.raises(DefinitionError):
        verifier(**overrides)


def test_policy_rejects_malformed_requirements_at_definition_time() -> None:
    malformed_roles: Any = (123,)

    with pytest.raises(DefinitionError):
        require_scopes("")
    with pytest.raises(DefinitionError):
        require_roles(*malformed_roles)


def test_policy_rejects_blank_name() -> None:
    with pytest.raises(DefinitionError, match="policy name must be non-empty text"):
        require_scopes("users:read", name="  ")


def test_issuer_normalizes_single_string_scopes_and_roles() -> None:
    token = issuer().issue("user-1", scopes="users:read", roles="admin", token_id="token-1")

    principal = verifier().authenticate(token)

    assert principal.scopes == ("users:read",)
    assert principal.roles == ("admin",)
    assert principal.token_id == "token-1"


def test_issuer_rejects_empty_token_id_and_shared_claim_names() -> None:
    with pytest.raises(DefinitionError):
        issuer().issue("user-1", token_id="")
    with pytest.raises(DefinitionError):
        issuer(scope_claim="roles", roles_claim="roles")


def test_issuer_rejects_a_non_datetime_now_with_a_definition_error() -> None:
    not_a_datetime: Any = "yesterday"

    with pytest.raises(DefinitionError, match="now must be a datetime"):
        issuer().issue("user-1", now=not_a_datetime)


def test_reserved_claim_error_names_the_offending_option() -> None:
    with pytest.raises(DefinitionError, match="scope_claim cannot override a registered"):
        issuer(scope_claim="sub")
