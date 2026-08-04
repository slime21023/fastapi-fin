"""HTTP endpoints for the complete Task API example."""

from fastapi_fin.application import ApplicationRouter, inject
from fastapi_fin.features import GuardDefinition

from . import policies
from .domain import TaskCreate, TaskView
from .providers import TaskService

SERVICE = inject(TaskService)
router = ApplicationRouter(prefix="/tasks", tags=("tasks",))


@router.get("/", response_model=list[TaskView])
def list_tasks(service: TaskService = SERVICE) -> list[TaskView]:
    return service.list()


@router.post(
    "/",
    response_model=TaskView,
    status_code=201,
    guards=(GuardDefinition(policies.admin_only, name="admin-only"),),
)
def create_task(
    payload: TaskCreate,
    service: TaskService = SERVICE,
) -> TaskView:
    return service.create(payload)
