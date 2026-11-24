"""HTTP endpoints for the complete Task API example."""

from fastapi import APIRouter

from fastapi_fin import FastAPISecurity, Inject, require_roles

from .domain import TaskCreate, TaskService, TaskView

security = FastAPISecurity()
router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.get("", response_model=list[TaskView])
async def list_tasks(service: Inject[TaskService]) -> list[TaskView]:
    return service.list()


@router.post(
    "",
    response_model=TaskView,
    status_code=201,
    dependencies=[security.require(require_roles("admin"))],
)
async def create_task(payload: TaskCreate, service: Inject[TaskService]) -> TaskView:
    return service.create(payload)
