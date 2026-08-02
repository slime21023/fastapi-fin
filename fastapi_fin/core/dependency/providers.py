"""Immutable provider declarations and registration."""

from collections.abc import Callable

from attrs import evolve, field, frozen, validators

from ..errors import DeclarationError, RegistrationError
from ..types import Scope, _validate_nonnegative_integer

ServiceToken = type[object] | str
ServiceFactory = Callable[..., object]


def _normalize_token(token: ServiceToken) -> ServiceToken:
    if isinstance(token, type):
        return token
    if isinstance(token, str) and token.strip():
        return token.strip()
    raise DeclarationError("service token must be a type or non-empty string")


def _validate_factory(factory: ServiceFactory) -> ServiceFactory:
    if not callable(factory):
        raise DeclarationError("service factory must be callable")
    return factory


def normalize_scope(value: str | Scope) -> Scope:
    """Normalize a scope name at provider registration time."""
    if isinstance(value, Scope):
        return value
    try:
        return Scope(value.lower())
    except (AttributeError, TypeError, ValueError) as error:
        raise DeclarationError(f"unsupported provider scope: {value!r}") from error


@frozen(slots=True, kw_only=True)
class Provider:
    """Immutable provider declaration for one service token."""

    token: ServiceToken = field(converter=_normalize_token)
    factory: ServiceFactory = field(converter=_validate_factory)
    scope: Scope = field(converter=normalize_scope)
    lazy: bool = field(default=True, validator=validators.instance_of(bool))


def _normalize_providers(values: tuple[Provider, ...]) -> tuple[Provider, ...]:
    normalized = tuple(values)
    if not all(isinstance(provider, Provider) for provider in normalized):
        raise DeclarationError("provider registry items must be Provider instances")
    tokens: set[ServiceToken] = set()
    for provider in normalized:
        if provider.token in tokens:
            raise RegistrationError(f"service token is already provided: {provider.token!r}")
        tokens.add(provider.token)
    return normalized


@frozen(slots=True, kw_only=True)
class ProviderRegistry:
    """Immutable provider registry whose updates return a new registry."""

    providers: tuple[Provider, ...] = field(
        factory=tuple,
        converter=_normalize_providers,
    )
    version: int = field(default=0, validator=_validate_nonnegative_integer)

    def provide(
        self,
        token: ServiceToken,
        factory: ServiceFactory | None = None,
        *,
        scope: str | Scope = Scope.TRANSIENT,
        lazy: bool = True,
    ) -> "ProviderRegistry":
        """Return a registry with one provider.

        A class token can omit ``factory`` and will construct itself.  This is
        the common case for services and controllers.
        """
        if factory is None:
            if not isinstance(token, type):
                raise DeclarationError("factory is required for string provider tokens")
            factory = token

        normalized_token = _normalize_token(token)
        if self.find(normalized_token) is not None:
            raise RegistrationError(f"service token is already provided: {normalized_token!r}")
        provider = Provider(
            token=normalized_token,
            factory=factory,
            scope=scope,
            lazy=lazy,
        )
        return evolve(self, providers=(*self.providers, provider), version=self.version + 1)

    def replace(
        self,
        token: ServiceToken,
        factory: ServiceFactory,
        *,
        scope: str | Scope = Scope.TRANSIENT,
        lazy: bool = True,
    ) -> "ProviderRegistry":
        """Return a new registry replacing one existing provider."""
        normalized_token = _normalize_token(token)
        if self.find(normalized_token) is None:
            raise RegistrationError(
                f"cannot replace an unprovided service token: {normalized_token!r}"
            )
        replacement = Provider(
            token=normalized_token,
            factory=factory,
            scope=scope,
            lazy=lazy,
        )
        return evolve(
            self,
            providers=tuple(
                replacement if provider.token == normalized_token else provider
                for provider in self.providers
            ),
            version=self.version + 1,
        )

    def find(self, token: ServiceToken) -> Provider | None:
        """Find a provider by token without resolving it."""
        normalized_token = _normalize_token(token)
        return next(
            (provider for provider in self.providers if provider.token == normalized_token),
            None,
        )


__all__ = [
    "Provider",
    "ProviderRegistry",
    "ServiceFactory",
    "ServiceToken",
    "normalize_scope",
]
