"""Provider implementations for the complete Task API example."""

from dishka import Provider, Scope, provide

from fastapi_fin import JwtVerifier, Module, TokenAuthenticator

from .domain import TaskCreate, TaskService, TaskView

JWT_ISSUER = "https://issuer.example"
JWT_AUDIENCE = "task-api"


class TaskRepository:
    """In-memory storage shared across requests."""

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


class _TaskService:
    """A request-scoped service that depends on the application repository."""

    def __init__(self, repository: TaskRepository) -> None:
        self._repository = repository

    def create(self, payload: TaskCreate) -> TaskView:
        return self._repository.create(payload)

    def list(self) -> list[TaskView]:
        return self._repository.list()


class _TaskProvider(Provider):
    repository = provide(TaskRepository, scope=Scope.APP)

    @provide(scope=Scope.REQUEST)
    def service(self, repository: TaskRepository) -> TaskService:
        return _TaskService(repository)


class _AuthProvider(Provider):
    def __init__(self, signing_key: str) -> None:
        super().__init__()
        self._signing_key = signing_key

    @provide(scope=Scope.APP)
    def authenticator(self) -> TokenAuthenticator:
        return JwtVerifier(
            key=self._signing_key,
            algorithms=("HS256",),
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
        )


tasks_module = Module("tasks", providers=(_TaskProvider(),), exports=(TaskService,))


def auth_module(signing_key: str) -> Module:
    return Module("auth", providers=(_AuthProvider(signing_key),), exports=(TokenAuthenticator,))
