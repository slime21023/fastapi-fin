import asyncio
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable

import pytest

from fastapi_fin.core import DeclarationError, GuardPolicy, GuardRule, RegistrationError


def test_guard_policy_evaluates_rules_by_priority() -> None:
    policy = GuardPolicy().combine(
        [
            GuardRule(name="is-admin", predicate=lambda subject: subject == "admin", priority=10),
            GuardRule(name="has-account", predicate=lambda subject: subject is not None),
        ]
    )

    assert policy.evaluate("admin") is True
    assert policy.evaluate("member") is False


def test_guard_policy_rejects_universal_and_restricted_combinations() -> None:
    with pytest.raises(RegistrationError):
        GuardPolicy.allow_all().add(
            GuardRule(name="is-admin", predicate=lambda subject: subject == "admin")
        )


def test_guard_policy_evaluates_async_predicates() -> None:
    async def is_admin(subject: object) -> bool:
        return subject == "admin"

    policy = GuardPolicy().add(GuardRule(name="is-admin", predicate=is_admin))

    assert asyncio.run(policy.evaluate_async("admin")) is True
    assert asyncio.run(policy.evaluate_async("member")) is False


def test_guard_sync_evaluation_closes_async_predicates() -> None:
    async def is_admin(_subject: object) -> bool:
        return True

    policy = GuardPolicy().add(GuardRule(name="async", predicate=is_admin))

    with pytest.raises(TypeError, match="evaluate_async"):
        policy.evaluate(object())


def test_guard_policy_rejects_non_boolean_predicate_results() -> None:
    sync_policy = GuardPolicy().add(
        GuardRule(
            name="invalid-sync",
            predicate=cast("Callable[[object], bool]", lambda _subject: "yes"),
        )
    )
    with pytest.raises(TypeError, match="must return bool"):
        sync_policy.evaluate(object())

    async def invalid_async(_subject: object) -> object:
        return cast("object", 1)

    async_policy = GuardPolicy().add(
        GuardRule(
            name="invalid-async",
            predicate=cast("Callable[[object], bool]", invalid_async),
        )
    )
    with pytest.raises(TypeError, match="must return bool"):
        asyncio.run(async_policy.evaluate_async(object()))


def test_guard_rule_rejects_non_callable_predicates() -> None:
    with pytest.raises(DeclarationError):
        GuardRule(name="invalid", predicate=cast("Callable[[object], bool]", object()))
