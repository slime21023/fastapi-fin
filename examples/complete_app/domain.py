"""Request and response models for the complete Task API example."""

from pydantic import BaseModel, Field


class TaskCreate(BaseModel):
    title: str = Field(min_length=1)


class TaskView(BaseModel):
    id: int
    title: str
    completed: bool
