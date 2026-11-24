"""Models and service contract for the complete Task API example."""

from typing import Protocol

from pydantic import BaseModel, Field


class TaskCreate(BaseModel):
    title: str = Field(min_length=1)


class TaskView(BaseModel):
    id: int
    title: str
    completed: bool


class TaskService(Protocol):
    def create(self, payload: TaskCreate) -> TaskView: ...

    def list(self) -> list[TaskView]: ...
