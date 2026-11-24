"""JWT issuing and verification with explicit security policy."""

from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime, timedelta
from importlib import import_module
from types import MappingProxyType, ModuleType
from uuid import uuid4

from attrs import define, field

from .._validation import bool_validator
from ..errors import DefinitionError
from .claims import AuthenticatedPrincipal
from .errors import InvalidTokenError, SecurityDependencyError

JwtKeyResolver = Callable[[Mapping[str, object]], object]


def _load_jwt() -> ModuleType:
    try:
        return import_module("jwt")
    except ImportError as error:
        raise SecurityDependencyError(
            "JWT support requires the security extra: "
            "run uv sync --extra security from the source checkout",
        ) from error


def _normalize_algorithms(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    try:
        normalized = tuple(dict.fromkeys(values))
    except TypeError as error:
        raise DefinitionError("JWT algorithms must be iterable") from error
    if not normalized or not all(isinstance(value, str) and value.strip() for value in normalized):
        raise DefinitionError("JWT algorithms must contain non-empty strings")
    if "none" in {value.lower() for value in normalized}:
        raise DefinitionError("JWT unsecured algorithm is not supported")
    return tuple(value.strip() for value in normalized)


def _normalize_claim_names(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    try:
        normalized = tuple(dict.fromkeys(values))
    except TypeError as error:
        raise DefinitionError("JWT required claims must be iterable") from error
    if not all(isinstance(value, str) and value.strip() for value in normalized):
        raise DefinitionError("JWT required claims must contain non-empty strings")
    return tuple(value.strip() for value in normalized)


def _normalize_audience(value: str | Iterable[str]) -> str | tuple[str, ...]:
    if isinstance(value, str):
        if not value.strip():
            raise DefinitionError("JWT audience must not be empty")
        return value.strip()
    try:
        normalized = tuple(dict.fromkeys(value))
    except TypeError as error:
        raise DefinitionError("JWT audience must be a string or iterable of strings") from error
    if not normalized or not all(isinstance(item, str) and item.strip() for item in normalized):
        raise DefinitionError("JWT audience must be a string or iterable of strings")
    return tuple(item.strip() for item in normalized)


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


def _normalize_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DefinitionError(f"{label} must be non-empty text")
    return value.strip()


def _normalize_optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _normalize_text(value, label)


def _normalize_issue_values(value: Iterable[str], label: str) -> tuple[str, ...]:
    if isinstance(value, str):
        values = (value,)
    else:
        try:
            values = tuple(value)
        except TypeError as error:
            raise DefinitionError(f"{label} must be iterable") from error
    if not all(isinstance(item, str) and item.strip() for item in values):
        raise DefinitionError(f"{label} must contain non-empty strings")
    return tuple(dict.fromkeys(item.strip() for item in values))


def _validate_claim_name(_instance: object, attribute: object, value: str) -> None:
    if value in {"iss", "sub", "aud", "iat", "exp", "jti"}:
        raise DefinitionError(f"{attribute} cannot override a registered JWT claim")


def _validate_lifetime(_instance: object, _attribute: object, value: timedelta) -> None:
    if not isinstance(value, timedelta) or value <= timedelta(0):
        raise DefinitionError("JWT lifetime must be positive")


def _validate_leeway(_instance: object, _attribute: object, value: int | float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise DefinitionError("JWT leeway must be a non-negative number")


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
    issuer: str = field(default="", converter=lambda value: _normalize_text(value, "JWT issuer"))
    audience: str | tuple[str, ...] = field(converter=_normalize_audience)
    required_claims: tuple[str, ...] = field(
        default=("exp", "iat", "iss", "sub", "aud"),
        converter=_normalize_claim_names,
    )
    expected_type: str | None = field(
        default="at+jwt",
        converter=lambda value: _normalize_optional_text(value, "JWT expected_type"),
    )
    require_jti: bool = field(default=True, validator=bool_validator("require_jti"))
    leeway: int | float = field(default=0, validator=_validate_leeway)
    scope_claim: str = field(
        default="scope",
        converter=lambda value: _normalize_text(value, "JWT scope_claim"),
        validator=_validate_claim_name,
    )
    roles_claim: str = field(
        default="roles",
        converter=lambda value: _normalize_text(value, "JWT roles_claim"),
        validator=_validate_claim_name,
    )

    def __attrs_post_init__(self) -> None:
        if (self.key is None) == (self.key_resolver is None):
            raise DefinitionError("JWT verifier requires exactly one key or key_resolver")
        if self.scope_claim == self.roles_claim:
            raise DefinitionError("JWT scope_claim and roles_claim must be different")
        if self.require_jti and "jti" not in self.required_claims:
            object.__setattr__(self, "required_claims", (*self.required_claims, "jti"))

    def authenticate(self, token: str) -> AuthenticatedPrincipal:
        """Verify one bearer token and return its validated principal."""
        if not isinstance(token, str) or not token.strip():
            raise InvalidTokenError("JWT token is required")
        jwt = _load_jwt()
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            if algorithm not in self.algorithms:
                raise InvalidTokenError("JWT algorithm is not trusted")
            if self.expected_type is not None and header.get("typ") != self.expected_type:
                raise InvalidTokenError("JWT type is not trusted")
            key = self.key_resolver(header) if self.key_resolver is not None else self.key
            payload = jwt.decode(
                token,
                key,
                algorithms=list(self.algorithms),
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={
                    "require": list(self.required_claims),
                    "verify_iat": True,
                },
            )
        except InvalidTokenError:
            raise
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as error:
            raise InvalidTokenError("JWT validation failed") from error
        if not isinstance(payload, dict):
            raise InvalidTokenError("JWT claims must be an object")
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


@define(frozen=True, slots=True, kw_only=True)
class JwtIssuer:
    """Issue short-lived JWT access tokens with reserved claims protected."""

    key: object
    algorithm: str = field(converter=lambda value: _normalize_text(value, "JWT algorithm"))
    issuer: str = field(converter=lambda value: _normalize_text(value, "JWT issuer"))
    audience: str | tuple[str, ...] = field(converter=_normalize_audience)
    lifetime: timedelta = field(
        default=timedelta(minutes=15),
        validator=_validate_lifetime,
    )
    token_type: str = field(
        default="at+jwt",
        converter=lambda value: _normalize_text(value, "JWT token_type"),
    )
    key_id: str | None = field(
        default=None,
        converter=lambda value: _normalize_optional_text(value, "JWT key_id"),
    )
    scope_claim: str = field(
        default="scope",
        converter=lambda value: _normalize_text(value, "JWT scope_claim"),
        validator=_validate_claim_name,
    )
    roles_claim: str = field(
        default="roles",
        converter=lambda value: _normalize_text(value, "JWT roles_claim"),
        validator=_validate_claim_name,
    )

    def __attrs_post_init__(self) -> None:
        if self.algorithm.lower() == "none":
            raise DefinitionError("JWT unsecured algorithm is not supported")
        if self.scope_claim == self.roles_claim:
            raise DefinitionError("JWT scope_claim and roles_claim must be different")
        if self.key_id is not None and not self.key_id:
            raise DefinitionError("JWT key_id must be non-empty when provided")

    def issue(  # noqa: PLR0913 — preserve the public keyword-only signing options.
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
        if not isinstance(subject, str) or not subject.strip():
            raise DefinitionError("JWT subject must not be empty")
        issued_at = now or datetime.now(UTC)
        if issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=UTC)
        if not isinstance(issued_at, datetime):
            raise DefinitionError("JWT now must be a datetime")
        normalized_token_id = (
            uuid4().hex if token_id is None else _normalize_text(token_id, "JWT token_id")
        )
        claims: dict[str, object] = {
            "iss": self.issuer,
            "sub": subject.strip(),
            "aud": self.audience,
            "iat": issued_at,
            "exp": issued_at + self.lifetime,
            "jti": normalized_token_id,
        }
        if additional_claims is not None:
            _merge_additional_claims(
                claims, additional_claims, (self.scope_claim, self.roles_claim, "kid")
            )
        normalized_scopes = _normalize_issue_values(scopes, "JWT scopes")
        normalized_roles = _normalize_issue_values(roles, "JWT roles")
        if normalized_scopes:
            claims[self.scope_claim] = " ".join(normalized_scopes)
        if normalized_roles:
            claims[self.roles_claim] = list(normalized_roles)
        headers = {"typ": self.token_type}
        if self.key_id is not None:
            headers["kid"] = self.key_id
        return _load_jwt().encode(
            claims,
            self.key,
            algorithm=self.algorithm,
            headers=headers,
        )


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
