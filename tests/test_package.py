import fastapi_fin


def test_package_exposes_v1_application_concepts() -> None:
    assert fastapi_fin.__version__ == "1.0.1"
    assert hasattr(fastapi_fin, "ApplicationDefinition")
    assert fastapi_fin.FastAPIAdapter.__name__ == "FastAPIAdapter"
    assert not hasattr(fastapi_fin, "ApplicationRegistry")
