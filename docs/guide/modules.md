# Modules and contracts

First define a service contract with a `Protocol`, abstract base class, or other type hint Dishka can identify, then let a module register the implementation. The contract is the DI key; if a factory's return type is a concrete class, use `@provide(provides=Contract, scope=...)` to specify the key to register explicitly.

- `providers`: pass Dishka `Provider` instances. `Module` assigns them to the Dishka component with the same name; do not set a provider's component in advance.
- `exports`: contracts exposed to other modules and the HTTP layer. Each contract can be exported by only one module, and it must be provided by that module.
- `requires`: contracts to be obtained from other modules or the host. Ordinary provider parameters still use the contract type; no component needs to be specified.

## Cross-module injection

Continuing from [Getting started](getting-started.md), add a `profiles` module to the same `app.py`. `ProfileService` depends on `UserDirectory` rather than on a data source implementation; `profiles` must list `UserDirectory` explicitly, even though `users` already exports it.

```python
class ProfileService:
    def __init__(self, directory: UserDirectory) -> None:
        self._directory = directory

    def display_name(self, user_id: int) -> str:
        return self._directory.find_name(user_id) or "Anonymous"


class ProfilesProvider(Provider):
    profile_service = provide(ProfileService, scope=Scope.APP)


profiles = Module(
    name="profiles",
    providers=(ProfilesProvider(),),
    exports=(ProfileService,),
    requires=(UserDirectory,),
)
fin_with_profiles = FinProxy(modules=(*fin.modules, profiles))
```

Services that are not exported are available to providers in the same module, but they do not appear in other modules or the default component through ordinary type resolution. This is the boundary of ordinary DI lookup, not a security sandbox: if the caller explicitly specifies a Dishka component, FastAPI-Fin does not block that direct access. `Inject[T]` in the HTTP layer uses the default component and should inject only exported service contracts.

## Declaration and assembly errors

Invalid module declarations raise `DefinitionError`; duplicate module names or exported contracts raise `AssemblyError` when the `FinProxy` is created. Only when the container is built does it check whether each `requires` entry is exported by another module or provided by the host's context, and validate the Dishka dependency graph. As a result, errors such as a missing provider, a cross-module dependency that is not required, and circular dependencies can be found before any request is handled.

A value that must be supplied by the host should be declared by the module in `requires` and provided through a [container scope](scopes.md); do not use `from_context` in the module's providers.
