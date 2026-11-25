import fastapi_fin


def test_package_exposes_contract_composition() -> None:
    assert fastapi_fin.__version__ == "0.9.1"
    assert fastapi_fin.Module.__name__ == "Module"
    assert fastapi_fin.FinComposition.__name__ == "FinComposition"
    assert fastapi_fin.FastAPIIntegration.__name__ == "FastAPIIntegration"
