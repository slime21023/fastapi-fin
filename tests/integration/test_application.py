from fastapi.testclient import TestClient
import pytest

from fastapi_fin import controller, get, module
from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationRegistry


@controller(prefix="/items")
class ItemController:
    @get("/{item_id}")
    def get_item(self, item_id: int) -> dict[str, int]:
        return {"item_id": item_id}


@module("public-api", prefix="/api", controllers=(ItemController,))
class PublicApiModule:
    pass


@pytest.mark.integration
def test_complete_module_to_http_request_flow() -> None:
    registry = ApplicationRegistry().module(PublicApiModule)
    app = FastAPIAdapter.create_app(registry)

    with TestClient(app) as client:
        response = client.get("/api/items/7")

    assert response.status_code == 200
    assert response.json() == {"item_id": 7}
