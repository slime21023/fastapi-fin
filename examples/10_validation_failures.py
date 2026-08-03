"""Show that invalid application graphs fail before the application starts."""

from collections.abc import Callable

from fastapi_fin.application import ApplicationDefinition, Scope, assemble, inject, provide, route
from fastapi_fin.errors import AssemblyError, DefinitionError


def expect_failure(label: str, operation: Callable[[], object]) -> str:
    try:
        operation()
    except (AssemblyError, DefinitionError) as error:
        return f"{label}: {type(error).__name__}"
    raise AssertionError(f"{label} unexpectedly succeeded")


def main() -> None:
    def endpoint() -> None:
        return None

    duplicate_route = ApplicationDefinition(
        routes=(route("/health", endpoint), route("/health", endpoint)),
    )

    class MissingService:
        pass

    missing_marker = inject(MissingService)

    def missing_endpoint(service: MissingService = missing_marker) -> object:
        return service

    missing_provider = ApplicationDefinition(
        routes=(route("/missing", missing_endpoint),),
    )

    class First:
        pass

    class Second:
        pass

    cyclic_providers = ApplicationDefinition(
        providers=(
            provide(First, dependencies=(Second,)),
            provide(Second, dependencies=(First,)),
        ),
    )

    failures = (
        expect_failure("duplicate route", lambda: assemble(duplicate_route)),
        expect_failure("missing provider", lambda: assemble(missing_provider)),
        expect_failure("provider cycle", lambda: assemble(cyclic_providers)),
    )

    assert failures == (
        "duplicate route: AssemblyError",
        "missing provider: AssemblyError",
        "provider cycle: AssemblyError",
    )
    assert Scope.APPLICATION.value == "application"
    print("10_validation_failures: OK")


if __name__ == "__main__":
    main()
