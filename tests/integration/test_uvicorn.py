"""Serve the library's lifespan with real Uvicorn servers.

In-process servers verify resource lifecycle through events; subprocess servers verify the
``uvicorn`` command line, multiple workers, and startup failure.
"""

from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

from fastapi import FastAPI
import httpx
import pytest
import uvicorn
import uvicorn_apps

pytestmark = pytest.mark.integration

APP_DIR = Path(__file__).resolve().parent
STARTUP_TIMEOUT_SECONDS = 20.0
STARTUP_MESSAGE = "Application startup complete"


def free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_until(condition: Callable[[], bool], description: str) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {description}")
        time.sleep(0.05)


@pytest.fixture
def events() -> list[str]:
    uvicorn_apps.EVENTS.clear()
    return uvicorn_apps.EVENTS


@contextmanager
def in_process_server(app: FastAPI) -> Iterator[str]:
    """Run Uvicorn in a thread and stop it gracefully, as a termination signal would."""
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        wait_until(lambda: server.started, "the in-process server to start")
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=STARTUP_TIMEOUT_SECONDS)
    assert not thread.is_alive(), "the in-process server did not shut down"


def test_server_creates_app_resources_lazily_and_closes_them_on_shutdown(
    events: list[str],
) -> None:
    with in_process_server(uvicorn_apps.app) as base_url:
        assert events == []

        first = httpx.get(f"{base_url}/hello/Ada")
        second = httpx.get(f"{base_url}/hello/Bob")

        assert first.json() == {"message": "Hello, Ada!"}
        assert second.json() == {"message": "Hello, Bob!"}
        assert events == ["database-opened"]

    assert events == ["database-opened", "database-closed"]


def test_server_can_warm_up_app_resources_before_serving(events: list[str]) -> None:
    with in_process_server(uvicorn_apps.warmed_up_app) as base_url:
        assert events == ["database-opened"]

        response = httpx.get(f"{base_url}/hello/Ada")

        assert response.json() == {"message": "Hello, Ada!"}
        assert events == ["database-opened"]

    assert events == ["database-opened", "database-closed"]


def uvicorn_command(app: str, port: int, *options: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "uvicorn",
        "--app-dir",
        str(APP_DIR),
        "--port",
        str(port),
        *options,
        app,
    ]


def stop_process_tree(process: subprocess.Popen[bytes]) -> None:
    if sys.platform == "win32":
        # Windows cannot deliver SIGTERM; kill the supervisor together with its workers.
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False
        )
    else:
        process.terminate()
    process.wait(timeout=STARTUP_TIMEOUT_SECONDS)


def serves_requests(url: str) -> bool:
    try:
        return httpx.get(url, timeout=2).status_code == httpx.codes.OK
    except httpx.HTTPError:
        return False


@pytest.mark.parametrize(
    ("options", "expected_startups"),
    [((), 1), (("--workers", "2"), 2)],
    ids=["single-process", "two-workers"],
)
def test_command_line_server_starts_one_container_per_worker(
    tmp_path: Path, options: tuple[str, ...], expected_startups: int
) -> None:
    port = free_port()
    log = tmp_path / "uvicorn.log"
    with log.open("wb") as output:
        process = subprocess.Popen(
            uvicorn_command("uvicorn_apps:app", port, *options),
            stdout=output,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_until(lambda: serves_requests(f"http://127.0.0.1:{port}/hello/Ada"), "the server")
            replies = [httpx.get(f"http://127.0.0.1:{port}/hello/Ada").json() for _ in range(6)]
        finally:
            stop_process_tree(process)

    assert replies == [{"message": "Hello, Ada!"}] * 6
    assert log.read_text(errors="replace").count(STARTUP_MESSAGE) == expected_startups


def test_command_line_server_refuses_to_start_when_a_route_injects_an_unexported_contract(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        uvicorn_command("uvicorn_apps:misconfigured_app", free_port()),
        capture_output=True,
        text=True,
        timeout=STARTUP_TIMEOUT_SECONDS,
        check=False,
        cwd=tmp_path,
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "AssemblyError" in output
    assert "not an exported contract" in output
    assert "Application startup failed" in output
    assert STARTUP_MESSAGE not in output
