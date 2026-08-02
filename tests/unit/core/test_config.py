from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable

import pytest

from fastapi_fin.core import (
    ConfigSnapshot,
    DeclarationError,
    RegistrationError,
    ResolutionError,
    SettingSpec,
)


def test_config_snapshot_parses_and_redacts_sensitive_values() -> None:
    specs = (
        SettingSpec(name="port", parser=int),
        SettingSpec(name="token", sensitive=True),
    )
    snapshot = ConfigSnapshot.load({"port": "8000", "token": "secret"}, specs)

    assert snapshot.get("port") == 8000
    assert snapshot.get_typed("port", int) == 8000
    assert snapshot.redacted() == (("port", 8000), ("token", "<redacted>"))
    assert [spec.name for spec in snapshot.specs] == ["port", "token"]


def test_config_snapshot_repr_redacts_sensitive_values() -> None:
    snapshot = ConfigSnapshot.load(
        {"token": "super-secret"},
        (SettingSpec(name="token", sensitive=True),),
    )

    rendered = repr(snapshot)

    assert "super-secret" not in rendered
    assert "<redacted>" in rendered


def test_config_snapshot_derives_sensitive_names_from_specs() -> None:
    snapshot = ConfigSnapshot(
        values=(("token", "super-secret"),),
        specs=(SettingSpec(name="token", sensitive=True),),
    )

    assert snapshot.sensitive_names == frozenset({"token"})
    assert snapshot.redacted() == (("token", "<redacted>"),)
    assert "super-secret" not in repr(snapshot)


def test_config_snapshot_rejects_missing_and_unknown_values() -> None:
    with pytest.raises(DeclarationError, match="missing"):
        ConfigSnapshot.load({}, (SettingSpec(name="token"),))
    with pytest.raises(DeclarationError, match="unknown"):
        ConfigSnapshot.load({"extra": True}, (SettingSpec(name="token", required=False),))


def test_optional_setting_defaults_are_parsed_and_loaded() -> None:
    spec = SettingSpec(
        name="port",
        parser=int,
        required=False,
        default="8000",
    )

    snapshot = ConfigSnapshot.load({}, (spec,))

    assert spec.has_default is True
    assert snapshot.get_typed("port", int) == 8000


def test_setting_rejects_contradictory_or_invalid_defaults() -> None:
    with pytest.raises(DeclarationError, match="cannot define a default"):
        SettingSpec(name="port", default=8000)

    with pytest.raises(DeclarationError, match="invalid configuration setting"):
        ConfigSnapshot.load(
            {},
            (SettingSpec(name="port", parser=int, required=False, default="invalid"),),
        )


def test_config_wraps_arbitrary_parser_exceptions_consistently() -> None:
    def parse(_value: object) -> object:
        raise RuntimeError("parser internals")

    spec = SettingSpec(name="value", parser=parse)
    with pytest.raises(DeclarationError, match="invalid configuration setting"):
        ConfigSnapshot.load({"value": "raw"}, (spec,))

    valid = ConfigSnapshot.load({"value": "raw"}, (SettingSpec(name="value"),))
    invalid_spec_snapshot = ConfigSnapshot(
        values=valid.values,
        specs=(spec,),
    )
    with pytest.raises(DeclarationError, match="invalid configuration setting"):
        invalid_spec_snapshot.replace("value", "new")


def test_config_snapshot_replace_returns_new_version() -> None:
    snapshot = ConfigSnapshot.load({"port": "8000"}, (SettingSpec(name="port", parser=int),))
    updated = snapshot.replace("port", 9000)

    assert snapshot.get("port") == 8000
    assert updated.get("port") == 9000
    assert updated.version == 1
    reparsed = snapshot.replace("port", "9001")
    assert reparsed.get("port") == 9001
    with pytest.raises(DeclarationError, match="invalid configuration setting"):
        snapshot.replace("port", "not-an-int")
    assert snapshot.get("port") == 8000
    with pytest.raises(ResolutionError):
        snapshot.get("missing")
    with pytest.raises(ResolutionError, match="not str"):
        snapshot.get_typed("port", str)
    with pytest.raises(DeclarationError):
        snapshot.get_typed("port", cast("type[str]", object()))


def test_config_snapshot_normalizes_direct_values_and_rejects_invalid_specs() -> None:
    snapshot = ConfigSnapshot(
        values=[(" port ", 8000)],
        sensitive_names=[" token "],
    )

    assert snapshot.values == (("port", 8000),)
    assert snapshot.sensitive_names == frozenset({"token"})

    with pytest.raises(DeclarationError):
        SettingSpec(name=" ")
    with pytest.raises(DeclarationError):
        SettingSpec(name="port", parser=cast("Callable[[object], object]", object()))
    with pytest.raises(RegistrationError):
        ConfigSnapshot.load(
            {"port": 8000},
            (SettingSpec(name="port"), SettingSpec(name=" port ")),
        )
