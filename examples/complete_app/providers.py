"""Provider implementations for the complete Task API example."""

from .domain import TaskCreate, TaskView

cleanup_log: list[str] = []


class TaskRepository:
    """An application-scoped in-memory repository used as a deterministic fake."""

    def __init__(self) -> None:
        self._next_id = 1
        self._tasks: dict[int, TaskView] = {}

    def create(self, payload: TaskCreate) -> TaskView:
        task = TaskView(id=self._next_id, title=payload.title, completed=False)
        self._tasks[task.id] = task
        self._next_id += 1
        return task

    def list(self) -> list[TaskView]:
        return list(self._tasks.values())


class TaskService:
    """A request-scoped service that depends on the application repository."""

    def __init__(self, repository: TaskRepository) -> None:
        self.repository = repository

    def create(self, payload: TaskCreate) -> TaskView:
        return self.repository.create(payload)

    def list(self) -> list[TaskView]:
        return self.repository.list()


def close_repository(_repository: object) -> None:
    cleanup_log.append("repository-closed")


def close_service(_service: object) -> None:
    cleanup_log.append("service-closed")


def reset_state() -> None:
    cleanup_log.clear()
