"""Application lifecycle hooks for the complete Task API example."""

events: list[str] = []


def startup() -> None:
    events.append("started")


def shutdown() -> None:
    events.append("stopped")


def reset_state() -> None:
    events.clear()
