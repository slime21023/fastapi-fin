import asyncio

import httpx

from fastapi_fin.adapters import FastAPIAdapter
from fastapi_fin.application import ApplicationDefinition, route


def test_complete_definition_to_http_flow() -> None:
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app = FastAPIAdapter.create_app(
        ApplicationDefinition(routes=(route("/health", health),)),
    )

    async def scenario() -> httpx.Response:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client,
        ):
            return await client.get("/health")

    response = asyncio.run(scenario())
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
