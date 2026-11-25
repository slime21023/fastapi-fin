"""Resolve an exported contract from a worker without a FastAPI app."""

import asyncio

from dishka import Provider, Scope, provide

from fastapi_fin import FinComposition, Module, open_container


class Slugifier:
    def slugify(self, title: str) -> str:
        return "-".join(title.lower().split())


class PublishingProvider(Provider):
    slugifier = provide(Slugifier, scope=Scope.APP)


async def main() -> None:
    publishing = Module("publishing", providers=(PublishingProvider(),), exports=(Slugifier,))
    async with open_container(FinComposition(modules=(publishing,))) as container:
        slugifier = await container.get(Slugifier)
        assert slugifier.slugify("  Contract First DI  ") == "contract-first-di"

    print("04_without_fastapi: OK")


if __name__ == "__main__":
    asyncio.run(main())
