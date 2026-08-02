from pathlib import Path
import subprocess
import sys

from fastapi_fin import FastAPIAdapter, __version__, get, get_route_metadata
from fastapi_fin.adapters import FastAPIAdapter as AppAdapter
from fastapi_fin.adapters import inject as package_inject
from fastapi_fin.adapters.dependencies import inject


def test_package_exposes_version() -> None:
    assert __version__ == "0.1.0"


def test_package_exports_route_metadata_reader() -> None:
    @get("/items")
    def endpoint() -> dict[str, str]:
        return {"status": "ok"}

    metadata = get_route_metadata(endpoint)

    assert metadata.path == "/items"


def test_fastapi_adapter_remains_a_lazy_root_export() -> None:
    assert FastAPIAdapter.__name__ == "FastAPIAdapter"


def test_adapter_package_exports_layered_implementation() -> None:
    assert AppAdapter is FastAPIAdapter
    assert package_inject is inject


def test_core_import_does_not_eagerly_import_fastapi() -> None:
    code = """
import builtins
import sys

real_import = builtins.__import__

def blocked_import(name, *args, **kwargs):
    if name == "fastapi" or name.startswith("fastapi."):
        raise ModuleNotFoundError("blocked for core import contract")
    return real_import(name, *args, **kwargs)

builtins.__import__ = blocked_import
import fastapi_fin
import fastapi_fin.application
import fastapi_fin.core

assert "fastapi" not in sys.modules
assert "FastAPIAdapter" not in fastapi_fin.__dict__
"""
    subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
    )
