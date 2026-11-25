from typing import Any

from dishka import Provider, Scope
import pytest

from fastapi_fin.errors import AssemblyError, DefinitionError
from fastapi_fin.modules import FinComposition, Module


def context_provider() -> Provider:
    provider = Provider()
    provider.from_context(int, scope=Scope.REQUEST)
    return provider


@pytest.mark.parametrize(
    ("name", "options", "message"),
    [
        ("  ", {}, "non-empty text"),
        (1, {}, "non-empty text"),
        ("a", {"providers": (object(),)}, "Provider instances"),
        ("a", {"providers": (Provider(component="other"),)}, "must not set a component"),
        ("a", {"providers": (context_provider(),)}, "must not use from_context"),
        ("a", {"exports": ("int",)}, "not strings or None"),
        ("a", {"exports": ([],)}, "hashable"),
        ("a", {"requires": (int, int)}, "more than once"),
        ("a", {"exports": (int,), "requires": (int,)}, "both exports and requires"),
    ],
)
def test_rejects_invalid_module(name: Any, options: dict[str, Any], message: str) -> None:
    with pytest.raises(DefinitionError, match=message):
        Module(name, **options)


@pytest.mark.parametrize(
    ("options", "error", "message"),
    [
        ({"modules": (object(),)}, DefinitionError, "Module values"),
        ({"modules": (Module("a"), Module(" a "))}, AssemblyError, "duplicate module name"),
        (
            {"modules": (Module("a", exports=(int,)), Module("b", exports=(int,)))},
            AssemblyError,
            "exported by modules 'a' and 'b'",
        ),
        ({"overrides": {int: 0}}, AssemblyError, "not an exported contract"),
    ],
)
def test_rejects_invalid_fin_proxy(
    options: dict[str, Any], error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        FinComposition(**options)


def test_overrides_are_immutable_snapshots() -> None:
    source: dict[object, object] = {int: 1}
    composition = FinComposition((Module("numbers", exports=(int,)),), source)
    source[int] = 2
    replaced = composition.with_overrides({int: 3})
    assert composition.overrides[int] == 1
    assert replaced.overrides[int] == 3
