from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
import secrets
import jwt
from fastapi import Depends, HTTPException, Request, status, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel


class OAuth2Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


class OAuth2Client(BaseModel):
    client_id: str
    client_secret: str
    redirect_uris: List[str]
    grant_types: List[str] = ["authorization_code", "refresh_token"]
    response_types: List[str] = ["code"]
    scopes: List[str] = ["openid", "profile", "email"]
    token_endpoint_auth_method: str = "client_secret_basic"


class OAuth2AuthorizationCode(BaseModel):
    code: str
    client_id: str
    redirect_uri: str
    expires_at: datetime
    scope: str
    user_id: str


class OAuth2Config(BaseModel):
    issuer: str
    token_expires_in: int = 3600  # 1 hour
    refresh_token_expires_in: int = 86400 * 30  # 30 days
    auth_code_expires_in: int = 600  # 10 minutes
    jwt_algorithm: str = "HS256"
    jwt_secret_key: str
    jwt_public_key: Optional[str] = None
    token_endpoint: str = "/oauth/token"
    authorization_endpoint: str = "/oauth/authorize"
    revocation_endpoint: str = "/oauth/revoke"
    introspection_endpoint: str = "/oauth/introspect"


class OAuth2Provider:
    def __init__(
        self,
        config: OAuth2Config,
        clients_store=None,
        tokens_store=None,
        auth_codes_store=None,
        user_getter=None,
        password_verifier=None,
    ):
        self.config = config
        self.clients = clients_store or {}
        self.tokens = tokens_store or {}
        self.auth_codes = auth_codes_store or {}
        self.user_getter = user_getter
        self.password_verifier = password_verifier

        # Create OAuth2 password bearer for dependency injection
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl=config.token_endpoint)

    def register_client(self, client: OAuth2Client) -> None:
        """Register a new OAuth2 client"""
        self.clients[client.client_id] = client

    def get_client(self, client_id: str) -> Optional[OAuth2Client]:
        """Get client by client_id"""
        return self.clients.get(client_id)

    def verify_client(self, client_id: str, client_secret: str) -> bool:
        """Verify client credentials"""
        client = self.get_client(client_id)
        if not client:
            return False
        return secrets.compare_digest(client.client_secret, client_secret)

    def create_authorization_code(
        self, client_id: str, redirect_uri: str, scope: str, user_id: str
    ) -> str:
        """Create a new authorization code"""
        if client_id not in self.clients:
            raise HTTPException(status_code=400, detail="Invalid client")

        client = self.clients[client_id]
        if redirect_uri not in client.redirect_uris:
            raise HTTPException(status_code=400, detail="Invalid redirect URI")

        code = secrets.token_urlsafe(32)
        expires_at = datetime.now(datetime.timezone.utc) + timedelta(
            seconds=self.config.auth_code_expires_in
        )

        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            expires_at=expires_at,
            scope=scope,
            user_id=user_id,
        )

        self.auth_codes[code] = auth_code
        return code

    def verify_authorization_code(
        self, code: str, client_id: str, redirect_uri: str
    ) -> Optional[OAuth2AuthorizationCode]:
        """Verify an authorization code"""
        auth_code = self.auth_codes.get(code)
        if not auth_code:
            return None

        if auth_code.expires_at < datetime.now(datetime.timezone.utc):
            del self.auth_codes[code]
            return None

        if auth_code.client_id != client_id or auth_code.redirect_uri != redirect_uri:
            return None

        return auth_code

    def create_token(
        self,
        client_id: str,
        user_id: str,
        scope: str,
        include_refresh_token: bool = True,
    ) -> OAuth2Token:
        """Create a new access token"""
        expires_in = self.config.token_expires_in
        expires_at = datetime.now(datetime.timezone.utc) + timedelta(seconds=expires_in)

        payload = {
            "sub": user_id,
            "iss": self.config.issuer,
            "iat": datetime.now(datetime.timezone.utc),
            "exp": expires_at,
            "client_id": client_id,
            "scope": scope,
        }

        access_token = jwt.encode(
            payload, self.config.jwt_secret_key, algorithm=self.config.jwt_algorithm
        )

        token_data = {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": expires_in,
            "scope": scope,
        }

        if include_refresh_token:
            refresh_token = secrets.token_urlsafe(32)
            refresh_expires_at = datetime.now(datetime.timezone.utc) + timedelta(
                seconds=self.config.refresh_token_expires_in
            )

            self.tokens[refresh_token] = {
                "client_id": client_id,
                "user_id": user_id,
                "scope": scope,
                "expires_at": refresh_expires_at,
            }

            token_data["refresh_token"] = refresh_token

        return OAuth2Token(**token_data)

    def refresh_token(
        self, refresh_token: str, client_id: str
    ) -> Optional[OAuth2Token]:
        """Refresh an access token using a refresh token"""
        token_data = self.tokens.get(refresh_token)
        if not token_data:
            return None

        if token_data["client_id"] != client_id:
            return None

        if token_data["expires_at"] < datetime.now(datetime.timezone.utc):
            del self.tokens[refresh_token]
            return None

        # Create new tokens
        new_token = self.create_token(
            client_id=client_id,
            user_id=token_data["user_id"],
            scope=token_data["scope"],
        )

        # Remove old refresh token
        del self.tokens[refresh_token]

        return new_token

    def revoke_token(self, token: str) -> bool:
        """Revoke a token"""
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False

    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify an access token and return its payload"""
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret_key,
                algorithms=[self.config.jwt_algorithm],
                options={"verify_aud": False},
            )
            return payload
        except jwt.PyJWTError:
            return None

    def get_current_user(
        self, token: str = Depends(OAuth2PasswordBearer(tokenUrl="token"))
    ):
        """FastAPI dependency to get the current user from a token"""
        payload = self.verify_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload

    def token_endpoint_handler(self) -> Callable:
        """Handle token endpoint requests"""

        async def _handler(
            form_data: Optional[OAuth2PasswordRequestForm] = Depends(),
            request: Optional[Request] = None,
        ):
            grant_type = form_data.grant_type or "password"

            # Verify client
            if not self.verify_client(form_data.client_id, form_data.client_secret):
                raise HTTPException(
                    status_code=401, detail="Invalid client credentials"
                )

            if grant_type == "password":
                if not self.user_getter or not self.password_verifier:
                    raise HTTPException(
                        status_code=501, detail="Password grant type not supported"
                    )

                user = self.user_getter(form_data.username)
                if not user or not self.password_verifier(user, form_data.password):
                    raise HTTPException(
                        status_code=401, detail="Invalid user credentials"
                    )

                token = self.create_token(
                    client_id=form_data.client_id,
                    user_id=form_data.username,
                    scope=" ".join(form_data.scopes),
                )

                return token.model_dump()

            elif grant_type == "authorization_code":
                if not request:
                    raise HTTPException(status_code=400, detail="Invalid request")

                code = request.query_params.get("code")
                redirect_uri = request.query_params.get("redirect_uri")

                if not code or not redirect_uri:
                    raise HTTPException(status_code=400, detail="Missing parameters")

                auth_code = self.verify_authorization_code(
                    code, form_data.client_id, redirect_uri
                )

                if not auth_code:
                    raise HTTPException(
                        status_code=400, detail="Invalid authorization code"
                    )

                # Remove used code
                del self.auth_codes[code]

                token = self.create_token(
                    client_id=form_data.client_id,
                    user_id=auth_code.user_id,
                    scope=auth_code.scope,
                )

                return token.model_dump()

            elif grant_type == "refresh_token":
                if not request:
                    raise HTTPException(status_code=400, detail="Invalid request")

                refresh_token = request.query_params.get("refresh_token")

                if not refresh_token:
                    raise HTTPException(status_code=400, detail="Missing refresh token")

                new_token = self.refresh_token(refresh_token, form_data.client_id)

                if not new_token:
                    raise HTTPException(status_code=400, detail="Invalid refresh token")

                return new_token.model_dump()

            else:
                raise HTTPException(
                    status_code=400, detail=f"Unsupported grant type: {grant_type}"
                )

        return _handler

    def get_router(self, prefix: str = "") -> APIRouter:
        """
        Get an APIRouter with OAuth2 endpoints that can be mounted in a FastAPI app

        Example:
            app = FastAPI()
            oauth2_provider = OAuth2Provider(config)
            app.include_router(oauth2_provider.get_router())
        """
        router = APIRouter()

        # Token endpoint
        token_url = f"{prefix}{self.config.token_endpoint}"
        router.add_api_route(
            token_url,
            self.token_endpoint_handler(),
            methods=["POST"],
            tags=["oauth2"],
        )

        # Update oauth2_scheme with the correct token URL
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl=token_url)

        return router

    def requires_auth(self, scopes: List[str] = None) -> Callable:
        """FastAPI dependency for requiring authentication with optional scope checking"""

        async def _dependency(token: str = Depends(self.oauth2_scheme)):
            payload = self.verify_token(token)
            if not payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            if scopes:
                token_scopes = payload.get("scope", "").split()
                for scope in scopes:
                    if scope not in token_scopes:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Insufficient permissions. Required scope: {scope}",
                            headers={"WWW-Authenticate": "Bearer"},
                        )

            return payload

        return _dependency
