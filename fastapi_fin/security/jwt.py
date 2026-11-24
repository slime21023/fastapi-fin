"""JWT issuing and verification with explicit security policy."""

from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime, timedelta
from importlib import import_module
from types import MappingProxyType, ModuleType
from uuid import uuid4

from attrs import Attribute, define, field

from .._validation import (
    bool_validator,
    normalize_text,
    normalize_text_tuple,
    optional_text_converter,
    text_converter,
    text_tuple_converter,
)
from ..errors import DefinitionError
from .claims import AuthenticatedPrincipal
from .errors import InvalidTokenError, SecurityDependencyError

JwtKeyResolver = Callable[[Mapping[str, object]], object]

_REGISTERED_CLAIMS = frozenset({"iss", "sub", "aud", "iat", "exp", "jti"})
# RFC 9068 media type for access tokens, not a secret.
_DEFAULT_TOKEN_TYPE = "at+jwt"  # noqa: S105  # nosec B105
_DEFAULT_LIFETIME = timedelta(minutes=15)


def _load_jwt() -> ModuleType:
    try:
        return import_module("jwt")
    except ImportError as error:
        raise SecurityDependencyError(
            "JWT support requires the security extra: "
            "run uv sync --extra security from the source checkout",
        ) from error


def _normalize_algorithms(values: Iterable[str] | str) -> tuple[str, ...]:
    algorithms = normalize_text_tuple(values, "JWT algorithms", allow_empty=False)
    if any(algorithm.lower() == "none" for algorithm in algorithms):
        raise DefinitionError("JWT unsecured algorithm is not supported")
    return algorithms


def _normalize_audience(value: str | Iterable[str]) -> str | tuple[str, ...]:
    if isinstance(value, str):
        return normalize_text(value, "JWT audience")
    return normalize_text_tuple(value, "JWT audience", allow_empty=False)


def _normalize_key_set(value: Mapping[str, object]) -> Mapping[str, object]:
    if (
        not isinstance(value, Mapping)
        or not value
        or not all(isinstance(key_id, str) and key_id.strip() for key_id in value)
    ):
        raise DefinitionError("JWT key set must contain non-empty key IDs")
    normalized = {key_id.strip(): key for key_id, key in value.items()}
    if len(normalized) != len(value):
        raise DefinitionError("JWT key set contains duplicate normalized key IDs")
    return MappingProxyType(normalized)


def _validate_claim_name(_instance: object, attribute: Attribute, value: str) -> None:
    if value in _REGISTERED_CLAIMS:
        raise DefinitionError(f"{attribute.name} cannot override a registered JWT claim")


def _validate_lifetime(_instance: object, _attribute: object, value: timedelta) -> None:
    if not isinstance(value, timedelta) or value <= timedelta(0):
        raise DefinitionError("JWT lifetime must be positive")


def _validate_leeway(_instance: object, _attribute: object, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        raise DefinitionError("JWT leeway must be a non-negative number")


def _claim_name_field(label: str, default: str) -> str:
    return field(
        default=default,
        converter=text_converter(label),
        validator=_validate_claim_name,
    )


def _require_distinct_claim_names(scope_claim: str, roles_claim: str) -> None:
    if scope_claim == roles_claim:
        raise DefinitionError("JWT scope_claim and roles_claim must be different")


@define(frozen=True, slots=True, kw_only=True)
class JwtKeySet:
    """Immutable key set used for safe local key rotation by ``kid``."""

    keys: Mapping[str, object] = field(factory=dict, converter=_normalize_key_set)

    def __attrs_post_init__(self) -> None:
        if not self.keys:
            raise DefinitionError("JWT key set must contain at least one key")

    def __call__(self, header: Mapping[str, object]) -> object:
        """Resolve the key identified by the token header's ``kid``."""
        key_id = header.get("kid")
        if not isinstance(key_id, str) or not key_id.strip():
            raise InvalidTokenError("JWT key ID is required")
        try:
            return self.keys[key_id]
        except KeyError as error:
            raise InvalidTokenError("JWT key is not trusted") from error


@define(frozen=True, slots=True, kw_only=True)
class JwtVerifier:
    """Verify JWT access tokens with an explicit issuer, audience and algorithm set."""

    key: object | None = None
    key_resolver: JwtKeyResolver | None = None
    algorithms: tuple[str, ...] = field(converter=_normalize_algorithms)
    issuer: str = field(converter=text_converter("JWT issuer"))
    audience: str | tuple[str, ...] = field(converter=_normalize_audience)
    required_claims: tuple[str, ...] = field(
        default=("exp", "iat", "iss", "sub", "aud"),
        converter=text_tuple_converter("JWT required claims"),
    )
    expected_type: str | None = field(
        default=_DEFAULT_TOKEN_TYPE, converter=optional_text_converter("JWT expected_type")
    )
    require_jti: bool = field(default=True, validator=bool_validator("require_jti"))
    leeway: float = field(default=0, validator=_validate_leeway)
    scope_claim: str = _claim_name_field("JWT scope_claim", "scope")
    roles_claim: str = _claim_name_field("JWT roles_claim", "roles")

    def __attrs_post_init__(self) -> None:
        if (self.key is None) == (self.key_resolver is None):
            raise DefinitionError("JWT verifier requires exactly one key or key_resolver")
        _require_distinct_claim_names(self.scope_claim, self.roles_claim)
        if self.require_jti and "jti" not in self.required_claims:
            object.__setattr__(self, "required_claims", (*self.required_claims, "jti"))

    def authenticate(self, token: str) -> AuthenticatedPrincipal:
        """Verify one bearer token and return its validated principal."""
        if not isinstance(token, str) or not token.strip():
            raise InvalidTokenError("JWT token is required")
        payload = self._decode(token)
        if self.require_jti and not isinstance(payload.get("jti"), str):
            raise InvalidTokenError("JWT ID is required")
        return AuthenticatedPrincipal(
            subject=payload["sub"],
            issuer=payload["iss"],
            audience=payload["aud"],
            scopes=payload.get(self.scope_claim, ()),
            roles=payload.get(self.roles_claim, ()),
            token_id=payload.get("jti"),
            token_type=self.expected_type,
            claims=payload,
        )

    def _decode(self, token: str) -> dict[str, object]:
        """Check the unverified header, then verify the signature and registered claims."""
        jwt = _load_jwt()
        try:
            header = jwt.get_unverified_header(token)
            self._require_trusted_header(header)
            key = self.key_resolver(header) if self.key_resolver is not None else self.key
            payload = jwt.decode(
                token,
                key,
                algorithms=list(self.algorithms),
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": list(self.required_claims), "verify_iat": True},
            )
        except InvalidTokenError:
            raise
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as error:
            raise InvalidTokenError("JWT validation failed") from error
        if not isinstance(payload, dict):
            raise InvalidTokenError("JWT claims must be an object")
        return payload

    def _require_trusted_header(self, header: Mapping[str, object]) -> None:
        if header.get("alg") not in self.algorithms:
            raise InvalidTokenError("JWT algorithm is not trusted")
        if self.expected_type is not None and header.get("typ") != self.expected_type:
            raise InvalidTokenError("JWT type is not trusted")


@define(frozen=True, slots=True, kw_only=True)
class JwtIssuer:
    """Issue short-lived JWT access tokens with reserved claims protected."""

    key: object
    algorithm: str = field(converter=text_converter("JWT algorithm"))
    issuer: str = field(converter=text_converter("JWT issuer"))
    audience: str | tuple[str, ...] = field(converter=_normalize_audience)
    lifetime: timedelta = field(default=_DEFAULT_LIFETIME, validator=_validate_lifetime)
    token_type: str = field(default=_DEFAULT_TOKEN_TYPE, converter=text_converter("JWT token_type"))
    key_id: str | None = field(default=None, converter=optional_text_converter("JWT key_id"))
    scope_claim: str = _claim_name_field("JWT scope_claim", "scope")
    roles_claim: str = _claim_name_field("JWT roles_claim", "roles")

    def __attrs_post_init__(self) -> None:
        if self.algorithm.lower() == "none":
            raise DefinitionError("JWT unsecured algorithm is not supported")
        _require_distinct_claim_names(self.scope_claim, self.roles_claim)

    def issue(  # noqa: PLR0913 - the public signing options are keyword-only on purpose.
        self,
        subject: str,
        *,
        scopes: Iterable[str] = (),
        roles: Iterable[str] = (),
        token_id: str | None = None,
        additional_claims: Mapping[str, object] | None = None,
        now: datetime | None = None,
    ) -> str:
        """Issue one signed access token with standard registered claims."""
        issued_at = _as_aware_datetime(now)
        claims: dict[str, object] = {
            "iss": self.issuer,
            "sub": normalize_text(subject, "JWT subject"),
            "aud": self.audience,
            "iat": issued_at,
            "exp": issued_at + self.lifetime,
            "jti": uuid4().hex if token_id is None else normalize_text(token_id, "JWT token_id"),
        }
        if additional_claims is not None:
            _merge_additional_claims(
                claims, additional_claims, (self.scope_claim, self.roles_claim, "kid")
            )
        claims.update(self._scope_and_role_claims(scopes, roles))
        return _load_jwt().encode(
            claims, self.key, algorithm=self.algorithm, headers=self._headers()
        )

    def _scope_and_role_claims(
        self, scopes: Iterable[str], roles: Iterable[str]
    ) -> dict[str, object]:
        claims: dict[str, object] = {}
        if normalized_scopes := normalize_text_tuple(scopes, "JWT scopes"):
            claims[self.scope_claim] = " ".join(normalized_scopes)
        if normalized_roles := normalize_text_tuple(roles, "JWT roles"):
            claims[self.roles_claim] = list(normalized_roles)
        return claims

    def _headers(self) -> dict[str, str]:
        headers = {"typ": self.token_type}
        if self.key_id is not None:
            headers["kid"] = self.key_id
        return headers


def _as_aware_datetime(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if not isinstance(now, datetime):
        raise DefinitionError("JWT now must be a datetime")
    return now if now.tzinfo is not None else now.replace(tzinfo=UTC)


def _merge_additional_claims(
    claims: dict[str, object],
    additional: Mapping[str, object],
    reserved: tuple[str, ...],
) -> None:
    if not isinstance(additional, Mapping):
        raise DefinitionError("additional_claims must be a mapping")
    if not all(isinstance(name, str) and name.strip() for name in additional):
        raise DefinitionError("additional_claims keys must be non-empty strings")
    if any(name in claims or name in reserved for name in additional):
        raise DefinitionError("additional_claims cannot override reserved JWT claims")
    claims.update(additional)


__all__ = ["JwtIssuer", "JwtKeyResolver", "JwtKeySet", "JwtVerifier"]
