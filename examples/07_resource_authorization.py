"""Give each resource its own access rules: scopes, roles, and owner checks."""

from collections.abc import Mapping
from secrets import token_urlsafe
from typing import Annotated, Protocol

from dishka import Provider, Scope, provide
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient

from fastapi_fin import (
    AuthenticatedPrincipal,
    FastAPIIntegration,
    FastAPISecurity,
    FinProxy,
    Inject,
    JwtIssuer,
    JwtVerifier,
    Module,
    TokenAuthenticator,
    require_roles,
    require_scopes,
)

ISSUER_URL = "https://issuer.example"
SECURITY = FastAPISecurity(scopes={"docs:read": "Read documents", "docs:write": "Edit documents"})


class DocumentAccess(Protocol):
    def can_edit(self, principal: AuthenticatedPrincipal, document_id: int) -> bool: ...


class OwnerOrAdminAccess:
    """Data-dependent rule: admins edit anything, everyone else only what they own."""

    def __init__(self, owners: Mapping[int, str]) -> None:
        self._owners = dict(owners)

    def can_edit(self, principal: AuthenticatedPrincipal, document_id: int) -> bool:
        return principal.has_role("admin") or self._owners.get(document_id) == principal.subject


class AuthProvider(Provider):
    def __init__(self, verifier: JwtVerifier) -> None:
        super().__init__()
        self._verifier = verifier

    @provide(scope=Scope.APP)
    def authenticator(self) -> TokenAuthenticator:
        return self._verifier


class DocumentProvider(Provider):
    @provide(scope=Scope.APP)
    def access(self) -> DocumentAccess:
        return OwnerOrAdminAccess(owners={1: "alice"})


documents = APIRouter(
    prefix="/documents", dependencies=[SECURITY.require(require_scopes("docs:read"))]
)
admin = APIRouter(prefix="/admin", dependencies=[SECURITY.require(require_roles("admin"))])


@documents.get("/{document_id}")
async def read_document(document_id: int) -> dict[str, int]:
    return {"id": document_id}


@documents.put("/{document_id}")
async def edit_document(
    document_id: int,
    access: Inject[DocumentAccess],
    principal: Annotated[AuthenticatedPrincipal, SECURITY.require(require_scopes("docs:write"))],
) -> dict[str, int | str]:
    if not access.can_edit(principal, document_id):
        raise HTTPException(status_code=403, detail="not the document owner")
    return {"id": document_id, "editor": principal.subject}


@admin.get("/stats")
async def read_stats() -> dict[str, int]:
    return {"documents": 1}


def create_app(fin: FinProxy) -> FastAPI:
    app = FastAPI(lifespan=FastAPIIntegration(fin).lifespan)
    app.include_router(documents)
    app.include_router(admin)
    return app


def bearer(
    issuer: JwtIssuer,
    subject: str,
    *,
    scopes: tuple[str, ...] = (),
    roles: tuple[str, ...] = (),
) -> dict[str, str]:
    return {"Authorization": f"Bearer {issuer.issue(subject, scopes=scopes, roles=roles)}"}


def main() -> None:
    key = token_urlsafe(32)
    issuer = JwtIssuer(key=key, algorithm="HS256", issuer=ISSUER_URL, audience="api")
    verifier = JwtVerifier(key=key, algorithms=("HS256",), issuer=ISSUER_URL, audience="api")
    fin = FinProxy(
        modules=(
            Module("auth", providers=(AuthProvider(verifier),), exports=(TokenAuthenticator,)),
            Module("documents", providers=(DocumentProvider(),), exports=(DocumentAccess,)),
        )
    )
    editor_scopes = ("docs:read", "docs:write")
    reader = bearer(issuer, "bob", scopes=("docs:read",))
    bob = bearer(issuer, "bob", scopes=editor_scopes)
    alice = bearer(issuer, "alice", scopes=editor_scopes)
    root = bearer(issuer, "root", scopes=editor_scopes, roles=("admin",))

    with TestClient(create_app(fin)) as client:
        assert client.get("/documents/1", headers=reader).status_code == 200
        read_only = client.put("/documents/1", headers=reader)
        assert read_only.status_code == 403
        assert "insufficient_scope" in read_only.headers["www-authenticate"]
        not_owner = client.put("/documents/1", headers=bob)
        assert not_owner.status_code == 403
        assert not_owner.json() == {"detail": "not the document owner"}
        assert client.put("/documents/1", headers=alice).json() == {"id": 1, "editor": "alice"}
        assert client.put("/documents/1", headers=root).status_code == 200
        assert client.get("/admin/stats", headers=bob).json() == {"detail": "forbidden"}
        assert client.get("/admin/stats", headers=root).json() == {"documents": 1}

    bob_owns = fin.with_overrides({DocumentAccess: OwnerOrAdminAccess(owners={1: "bob"})})
    with TestClient(create_app(bob_owns)) as client:
        assert client.put("/documents/1", headers=bob).status_code == 200
        assert client.put("/documents/1", headers=alice).status_code == 403

    print("07_resource_authorization: OK")


if __name__ == "__main__":
    main()
