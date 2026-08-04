"""Smoke-test every executable example as part of the integration layer."""

from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_SCRIPTS = tuple(
    ROOT / "examples" / name
    for name in (
        "01_minimal_routes.py",
        "02_dependency_injection.py",
        "03_guard_and_interceptor.py",
        "04_lifecycle_events.py",
        "05_request_response.py",
        "06_scopes_and_cleanup.py",
        "07_configuration.py",
        "08_events_and_cache.py",
        "09_complete_pipeline.py",
        "10_validation_failures.py",
        "11_security_jwt.py",
    )
)


@pytest.mark.integration
@pytest.mark.parametrize("script", EXAMPLE_SCRIPTS, ids=lambda path: path.stem)
def test_executable_example_runs(script: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.rstrip().endswith("OK")


@pytest.mark.integration
def test_complete_application_example_runs() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "examples.complete_app"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.rstrip() == "complete_app: OK"
