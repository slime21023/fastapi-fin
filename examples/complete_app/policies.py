"""Framework-independent policies for the complete Task API example."""

from collections.abc import Awaitable, Callable

audit_log: list[str] = []


def admin_only(subject: object) -> bool:
    return getattr(subject, "headers", {}).get("X-Role") == "admin"


async def audit(
    next_call: Callable[[tuple[object, ...], dict[str, object]], Awaitable[object]],
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> object:
    audit_log.append("request")
    return await next_call(args, kwargs)


def reset_state() -> None:
    audit_log.clear()
