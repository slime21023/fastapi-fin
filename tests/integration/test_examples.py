"""Smoke-test every executable example as part of the integration layer."""

from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_SCRIPTS = tuple(
    ROOT / "examples" / name
    for name in (
        "01_modules_and_contracts.py",
        "02_scopes_and_finalization.py",
        "03_testing_overrides.py",
        "04_without_fastapi.py",
        "05_validation_failures.py",
        "06_security_jwt.py",
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

    assert result.stdout.rstrip() == f"{script.stem}: OK"


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
