"""HTTP endpoints for the complete Task API example."""

from fastapi_fin.application import inject

from .domain import TaskCreate, TaskView
from .providers import TaskService

SERVICE = inject(TaskService)


def list_tasks(service: TaskService = SERVICE) -> list[TaskView]:
    return service.list()


def create_task(
    payload: TaskCreate,
    service: TaskService = SERVICE,
) -> TaskView:
    return service.create(payload)
