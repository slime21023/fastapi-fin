from typing import Dict, List, Optional, Any
import time
import base64
import hashlib
import jwt
from fastapi import (
    HTTPException,
    Request,
    status,
    APIRouter,
)
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from pydantic import BaseModel

from .oauth2 import OAuth2Provider, OAuth2Config, OAuth2Token


class OIDCUserInfo(BaseModel):
    """OpenID Connect UserInfo data model"""

    sub: str
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    middle_name: Optional[str] = None
    nickname: Optional[str] = None
    preferred_username: Optional[str] = None
    profile: Optional[str] = None
    picture: Optional[str] = None
    website: Optional[str] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    gender: Optional[str] = None
    birthdate: Optional[str] = None
    zoneinfo: Optional[str] = None
    locale: Optional[str] = None
    phone_number: Optional[str] = None
    phone_number_verified: Optional[bool] = None
    address: Optional[Dict[str, str]] = None
    updated_at: Optional[int] = None


class OIDCConfig(OAuth2Config):
    """OpenID Connect configuration"""

    userinfo_endpoint: str = "/oidc/userinfo"
    jwks_uri: str = "/oidc/.well-known/jwks.json"
    discovery_endpoint: str = "/.well-known/openid-configuration"
    id_token_signing_alg: str = "RS256"
    id_token_encryption_alg: Optional[str] = None
    id_token_encryption_enc: Optional[str] = None
    subject_types_supported: List[str] = ["public"]
    claims_supported: List[str] = [
        "sub",
        "iss",
        "auth_time",
        "acr",
        "name",
        "given_name",
        "family_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "email",
        "email_verified",
        "locale",
        "zoneinfo",
    ]


class OIDCProvider(OAuth2Provider):
    """
    OpenID Connect Provider implementation that extends OAuth2Provider
    """

    def __init__(
        self,
        config: OIDCConfig,
        clients_store=None,
        tokens_store=None,
        auth_codes_store=None,
        user_info_getter=None,
        user_getter=None,
        password_verifier=None,
    ):
        super().__init__(
            config=config,
            clients_store=clients_store,
            tokens_store=tokens_store,
            auth_codes_store=auth_codes_store,
            user_getter=user_getter,
            password_verifier=password_verifier,
        )
        self.config = config
        self.user_info_getter = user_info_getter

        # Create OAuth2 authorization code bearer for dependency injection
        self.oauth2_auth_code_scheme = OAuth2AuthorizationCodeBearer(
            authorizationUrl=config.authorization_endpoint,
            tokenUrl=config.token_endpoint,
        )

    def create_id_token(
        self,
        user_id: str,
        client_id: str,
        nonce: Optional[str] = None,
        auth_time: Optional[int] = None,
        access_token: Optional[str] = None,
        code: Optional[str] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create an OpenID Connect ID Token
        """
        now = int(time.time())
        expires_at = now + self.config.token_expires_in

        # Get user info for ID token claims
        user_info = {}
        if self.user_info_getter:
            user_info = self.user_info_getter(user_id)
            if isinstance(user_info, OIDCUserInfo):
                user_info = user_info.dict(exclude_none=True)

        # Base claims
        payload = {
            "iss": self.config.issuer,
            "sub": user_id,
            "aud": client_id,
            "exp": expires_at,
            "iat": now,
        }

        # Add auth_time if available
        if auth_time:
            payload["auth_time"] = auth_time

        # Add nonce if provided
        if nonce:
            payload["nonce"] = nonce

        # Add at_hash if access_token is provided
        if access_token:
            payload["at_hash"] = self._compute_hash(access_token)

        # Add c_hash if code is provided
        if code:
            payload["c_hash"] = self._compute_hash(code)

        # Add extra claims
        if extra_claims:
            payload.update(extra_claims)

        # Add user info claims
        if user_info:
            for key, value in user_info.items():
                if key != "sub":  # Don't override sub
                    payload[key] = value

        # Sign the ID token
        return jwt.encode(
            payload, self.config.jwt_secret_key, algorithm=self.config.jwt_algorithm
        )

    def _compute_hash(self, value: str) -> str:
        """
        Compute a hash value for the at_hash or c_hash claim
        """
        digest = hashlib.sha256(value.encode()).digest()
        hash_value = base64.urlsafe_b64encode(digest[:16]).decode().rstrip("=")
        return hash_value

    def create_token(
        self,
        client_id: str,
        user_id: str,
        scope: str,
        include_refresh_token: bool = True,
        nonce: Optional[str] = None,
        auth_time: Optional[int] = None,
        code: Optional[str] = None,
    ) -> OAuth2Token:
        """
        Override create_token to include ID token for OpenID Connect
        """
        # Get the base OAuth2 token
        token = super().create_token(
            client_id=client_id,
            user_id=user_id,
            scope=scope,
            include_refresh_token=include_refresh_token,
        )

        # Check if openid scope is requested
        scopes = scope.split()
        if "openid" in scopes:
            # Create ID token
            id_token = self.create_id_token(
                user_id=user_id,
                client_id=client_id,
                nonce=nonce,
                auth_time=auth_time,
                access_token=token.access_token,
                code=code,
            )

            # Add ID token to the response
            token_dict = token.model_dump()
            token_dict["id_token"] = id_token
            token = OAuth2Token(**token_dict)

        return token

    def create_authorization_code(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        user_id: str,
        nonce: Optional[str] = None,
        state: Optional[str] = None,
    ) -> str:
        """
        Override create_authorization_code to include OIDC parameters
        """
        code = super().create_authorization_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            user_id=user_id,
        )

        # Add OIDC specific parameters to the auth code
        auth_code = self.auth_codes.get(code)
        if auth_code and nonce:
            auth_code_dict = auth_code.model_dump()
            auth_code_dict["nonce"] = nonce
            auth_code_dict["auth_time"] = int(time.time())
            if state:
                auth_code_dict["state"] = state

            # Update the auth code
            self.auth_codes[code] = auth_code_dict

        return code

    def userinfo_endpoint_handler(self):
        """
        Handle userinfo endpoint requests
        """

        async def _handler(request: Request):
            # Get the access token from the Authorization header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authorization header",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            token = auth_header.split(" ")[1]

            # Verify the token
            payload = self.verify_token(token)
            if not payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )

            # Check if token has openid scope
            scopes = payload.get("scope", "").split()
            if "openid" not in scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Token does not have openid scope",
                    headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
                )

            # Get user info
            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Invalid token payload",
                )

            # Get user info from the getter function
            if not self.user_info_getter:
                raise HTTPException(
                    status_code=status.HTTP_501_NOT_IMPLEMENTED,
                    detail="UserInfo endpoint not implemented",
                )

            user_info = self.user_info_getter(user_id)
            if not user_info:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found",
                )

            # Convert to dict if it's a model
            if isinstance(user_info, OIDCUserInfo):
                user_info = user_info.dict(exclude_none=True)

            # Ensure sub is present and matches
            user_info["sub"] = user_id

            # Filter claims based on requested scopes
            filtered_info = {"sub": user_id}

            if "profile" in scopes:
                profile_claims = [
                    "name",
                    "family_name",
                    "given_name",
                    "middle_name",
                    "nickname",
                    "preferred_username",
                    "profile",
                    "picture",
                    "website",
                    "gender",
                    "birthdate",
                    "zoneinfo",
                    "locale",
                    "updated_at",
                ]
                for claim in profile_claims:
                    if claim in user_info:
                        filtered_info[claim] = user_info[claim]

            if "email" in scopes and "email" in user_info:
                filtered_info["email"] = user_info["email"]
                if "email_verified" in user_info:
                    filtered_info["email_verified"] = user_info["email_verified"]

            if "phone" in scopes and "phone_number" in user_info:
                filtered_info["phone_number"] = user_info["phone_number"]
                if "phone_number_verified" in user_info:
                    filtered_info["phone_number_verified"] = user_info[
                        "phone_number_verified"
                    ]

            if "address" in scopes and "address" in user_info:
                filtered_info["address"] = user_info["address"]

            return JSONResponse(content=filtered_info)

        return _handler

    def discovery_endpoint_handler(self):
        """
        Handle OpenID Connect discovery endpoint
        """

        async def _handler(request: Request):
            base_url = str(request.base_url).rstrip("/")

            discovery_data = {
                "issuer": self.config.issuer,
                "authorization_endpoint": f"{base_url}{self.config.authorization_endpoint}",
                "token_endpoint": f"{base_url}{self.config.token_endpoint}",
                "userinfo_endpoint": f"{base_url}{self.config.userinfo_endpoint}",
                "jwks_uri": f"{base_url}{self.config.jwks_uri}",
                "response_types_supported": [
                    "code",
                    "token",
                    "id_token",
                    "code token",
                    "code id_token",
                    "token id_token",
                    "code token id_token",
                ],
                "subject_types_supported": self.config.subject_types_supported,
                "id_token_signing_alg_values_supported": [
                    self.config.id_token_signing_alg
                ],
                "scopes_supported": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                ],
                "claims_supported": self.config.claims_supported,
                "grant_types_supported": ["authorization_code", "refresh_token"],
            }

            # Add encryption algorithms if configured
            if self.config.id_token_encryption_alg:
                discovery_data["id_token_encryption_alg_values_supported"] = [
                    self.config.id_token_encryption_alg
                ]

            if self.config.id_token_encryption_enc:
                discovery_data["id_token_encryption_enc_values_supported"] = [
                    self.config.id_token_encryption_enc
                ]

            return JSONResponse(content=discovery_data)

        return _handler

    def get_router(self, prefix: str = "") -> APIRouter:
        """
        Get an APIRouter with OIDC endpoints that can be mounted in a FastAPI app

        Example:
            app = FastAPI()
            oidc_provider = OIDCProvider(config)
            app.include_router(oidc_provider.get_router())
        """
        # Get the base OAuth2 router
        router = super().get_router(prefix)

        # Add OIDC specific routes
        userinfo_url = f"{prefix}{self.config.userinfo_endpoint}"
        discovery_url = f"{prefix}{self.config.discovery_endpoint}"

        router.add_api_route(
            userinfo_url,
            self.userinfo_endpoint_handler(),
            methods=["GET", "POST"],
            tags=["oidc"],
        )

        router.add_api_route(
            discovery_url,
            self.discovery_endpoint_handler(),
            methods=["GET"],
            tags=["oidc"],
        )

        return router

    def requires_auth(self, scopes: List[str] = None):
        """
        FastAPI dependency for requiring authentication with optional scope checking
        """
        return super().requires_auth(scopes)

    def get_user_info(self, token_payload: Dict) -> Optional[OIDCUserInfo]:
        """
        Get user info from token payload
        """
        user_id = token_payload.get("sub")
        if not user_id or not self.user_info_getter:
            return None

        return self.user_info_getter(user_id)
