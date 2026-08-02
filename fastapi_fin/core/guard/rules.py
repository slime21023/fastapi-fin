"""Declarative authorization rules independent from FastAPI."""

from collections.abc import Awaitable, Callable, Iterable
from inspect import isawaitable, iscoroutine

from attrs import evolve, field, frozen, validators

from ..errors import DeclarationError, RegistrationError
from ..types import _validate_integer

GuardPredicate = Callable[[object], bool | Awaitable[bool]]


def _normalize_name(name: str) -> str:
    if not isinstance(name, str):
        raise DeclarationError("guard name must be a string")
    normalized = name.strip()
    if not normalized:
        raise DeclarationError("guard name must not be empty")
    return normalized


def _validate_predicate(
    _instance: object,
    _attribute: object,
    predicate: GuardPredicate,
) -> None:
    if not callable(predicate):
        raise DeclarationError("guard predicate must be callable")


def _validate_rules(
    _instance: object,
    _attribute: object,
    rules: "tuple[GuardRule, ...]",
) -> None:
    names: set[str] = set()
    has_universal = False
    for rule in rules:
        if not isinstance(rule, GuardRule):
            raise DeclarationError("guard policy rules must be GuardRule instances")
        if rule.name in names:
            raise RegistrationError(f"guard rule is already registered: {rule.name!r}")
        if rule.universal and rules != (rule,):
            raise RegistrationError("universal guard cannot be combined with restricted rules")
        if has_universal:
            raise RegistrationError("restricted guard cannot be combined with a universal rule")
        names.add(rule.name)
        has_universal = has_universal or rule.universal


@frozen(slots=True, kw_only=True)
class GuardRule:
    """One named authorization predicate."""

    name: str = field(converter=_normalize_name)
    predicate: GuardPredicate = field(validator=_validate_predicate)
    priority: int = field(default=0, validator=_validate_integer)
    universal: bool = field(default=False, validator=validators.instance_of(bool))


@frozen(slots=True, kw_only=True)
class GuardPolicy:
    """Immutable ordered set of authorization rules."""

    rules: tuple[GuardRule, ...] = field(
        factory=tuple,
        converter=tuple,
        validator=_validate_rules,
    )

    @classmethod
    def allow_all(cls) -> "GuardPolicy":
        """Create a policy explicitly allowing every subject."""
        return cls(
            rules=(GuardRule(name="allow-all", predicate=lambda _subject: True, universal=True),)
        )

    def add(self, rule: GuardRule) -> "GuardPolicy":
        """Return a policy with a validated additional rule."""
        if any(existing.name == rule.name for existing in self.rules):
            raise RegistrationError(f"guard rule is already registered: {rule.name!r}")
        if rule.universal and self.rules:
            raise RegistrationError("universal guard cannot be combined with restricted rules")
        if any(existing.universal for existing in self.rules):
            raise RegistrationError("restricted guard cannot be combined with a universal rule")
        return evolve(self, rules=(*self.rules, rule))

    def combine(self, rules: Iterable[GuardRule]) -> "GuardPolicy":
        """Return a policy after adding rules in declaration order."""
        policy = self
        for rule in rules:
            policy = policy.add(rule)
        return policy

    def evaluate(self, subject: object) -> bool:
        """Evaluate all rules from highest to lowest priority."""
        for rule in sorted(self.rules, key=lambda item: -item.priority):
            result = rule.predicate(subject)
            if isawaitable(result):
                if iscoroutine(result):
                    result.close()
                raise TypeError("async guard predicates require evaluate_async")
            if not isinstance(result, bool):
                raise TypeError("guard predicates must return bool")
            if not result:
                return False
        return True

    async def evaluate_async(self, subject: object) -> bool:
        """Evaluate sync or async predicates from highest to lowest priority."""
        for rule in sorted(self.rules, key=lambda item: -item.priority):
            result = rule.predicate(subject)
            allowed = await result if isawaitable(result) else result
            if not isinstance(allowed, bool):
                raise TypeError("guard predicates must return bool")
            if not allowed:
                return False
        return True
