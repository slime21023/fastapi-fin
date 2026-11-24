import fastapi_fin


def test_package_exposes_v2_contract_composition() -> None:
    assert fastapi_fin.__version__ == "2.0.0"
    assert fastapi_fin.Module.__name__ == "Module"
    assert fastapi_fin.Application.__name__ == "Application"
    assert fastapi_fin.FastAPIIntegration.__name__ == "FastAPIIntegration"
    assert not hasattr(fastapi_fin, "ApplicationDefinition")
