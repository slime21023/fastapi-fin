"""Parse application settings and redact sensitive values."""

from fastapi_fin.features import Configuration, SettingDefinition


def parse_bool(value: object) -> bool:
    return str(value).lower() in {"1", "true", "yes"}


def main() -> None:
    settings = (
        SettingDefinition("port", int),
        SettingDefinition("debug", parse_bool, required=False, default="false"),
        SettingDefinition("api_key", str, sensitive=True),
    )
    configuration = Configuration.load(
        {"port": "8080", "api_key": "demo-secret"},
        settings,
    )

    assert configuration.get("port") == 8080
    assert configuration.get("debug") is False
    assert configuration.redacted() == {
        "port": 8080,
        "debug": False,
        "api_key": "<redacted>",
    }
    assert "demo-secret" not in repr(configuration)
    print("07_configuration: OK")


if __name__ == "__main__":
    main()
