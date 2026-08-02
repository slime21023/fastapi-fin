from typing import cast

import pytest

from fastapi_fin.application import CompiledApplication
from fastapi_fin.core import (
    CachePolicy,
    ConfigSnapshot,
    ContainerSnapshot,
    DeclarationError,
    EventSubscription,
    GuardRule,
    HttpMethod,
    InterceptorSpec,
    MetadataSnapshot,
    normalize_methods,
    normalize_path,
)


def test_normalize_path_adds_leading_slash() -> None:
    assert normalize_path("users") == "/users"


def test_normalize_methods_is_case_insensitive_and_deduplicated() -> None:
    assert normalize_methods(["get", HttpMethod.GET, "POST"]) == (
        HttpMethod.GET,
        HttpMethod.POST,
    )


@pytest.mark.parametrize("path", ["", "users list", "/users?active=true", "/users#fragment"])
def test_invalid_path_fails_during_normalization(path: str) -> None:
    with pytest.raises(DeclarationError):
        normalize_path(path)


def test_invalid_method_fails_during_normalization() -> None:
    with pytest.raises(DeclarationError, match="unsupported HTTP method"):
        normalize_methods("FETCH")

    with pytest.raises(DeclarationError, match="iterable"):
        normalize_methods(cast("list[str]", None))


def test_numeric_options_reject_bool_subclasses() -> None:
    with pytest.raises(TypeError):
        CachePolicy(ttl=True)
    with pytest.raises(TypeError):
        CachePolicy(max_entries=True)
    with pytest.raises(TypeError):
        GuardRule(name="guard", predicate=lambda _subject: True, priority=True)
    with pytest.raises(TypeError):
        InterceptorSpec(
            name="interceptor", handler=lambda next_call, _args, _kwargs: next_call(), order=True
        )
    with pytest.raises(TypeError):
        InterceptorSpec(
            name="interceptor", handler=lambda next_call, _args, _kwargs: next_call(), retries=True
        )
    with pytest.raises(TypeError):
        InterceptorSpec(
            name="interceptor", handler=lambda next_call, _args, _kwargs: next_call(), timeout=True
        )
    with pytest.raises(TypeError):
        EventSubscription(event_type=object, handler=lambda _event: None, priority=True)
    with pytest.raises(TypeError):
        ContainerSnapshot(version=True)
    with pytest.raises(TypeError):
        ConfigSnapshot(version=True)
    with pytest.raises(TypeError):
        MetadataSnapshot(version=True)
    with pytest.raises(TypeError):
        CompiledApplication(registry_version=True)


def test_time_options_reject_non_finite_values_and_normalize_integers() -> None:
    assert CachePolicy(ttl=1).ttl == 1.0
    with pytest.raises(ValueError, match="finite and positive"):
        CachePolicy(ttl=float("nan"))
    with pytest.raises(ValueError, match="finite and positive"):
        CachePolicy(ttl=float("inf"))
    with pytest.raises(ValueError, match="finite and positive"):
        InterceptorSpec(
            name="interceptor",
            handler=lambda next_call, _args, _kwargs: next_call(),
            timeout=float("nan"),
        )
