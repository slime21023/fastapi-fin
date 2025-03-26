from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Tuple, Callable
from datetime import datetime, timedelta
import jwt
import uuid

class TokenData(BaseModel):
    """JWT 令牌數據模型"""

    sub: str
    scopes: List[str] = []
    exp: Optional[datetime] = None
    iat: Optional[datetime] = None
    jti: Optional[str] = None
    extra: Dict[str, Any] = {}


class OAuth2Helper:
    """FastAPI OAuth2 助手類"""

    def __init__(
        self,
        token_url: str,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 30,
        scopes: Dict[str, str] = None,
        auto_error: bool = True,
    ):
        """
        初始化 OAuth2 助手

        參數:
            token_url: OAuth2 令牌端點的 URL
            secret_key: 用於簽署 JWT 的密鑰
            algorithm: JWT 簽署算法
            access_token_expire_minutes: 訪問令牌的過期時間（分鐘）
            refresh_token_expire_days: 刷新令牌的過期時間（天）
            scopes: 可用權限範圍的字典 {scope_name: description}
            auto_error: 是否自動拋出驗證錯誤
        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.oauth2_scheme = OAuth2PasswordBearer(
            tokenUrl=token_url, scopes=scopes or {}, auto_error=auto_error
        )
        self.access_token_expire = timedelta(minutes=access_token_expire_minutes)
        self.refresh_token_expire = timedelta(days=refresh_token_expire_days)
        self.auto_error = auto_error

    def create_access_token(
        self,
        subject: str,
        scopes: List[str] = None,
        expires_delta: Optional[timedelta] = None,
        extra_data: Dict[str, Any] = None,
    ) -> str:
        """
        創建 JWT 訪問令牌

        參數:
            subject: 令牌主題（通常是用戶 ID）
            scopes: 權限範圍列表
            expires_delta: 自定義過期時間
            extra_data: 要包含在令牌中的額外數據

        返回:
            編碼的 JWT 令牌
        """
        to_encode = {
            "sub": subject,
            "scopes": scopes or [],
            "exp": datetime.now(datetime.timezone.utc)
            + (expires_delta or self.access_token_expire),
            "iat": datetime.now(datetime.timezone.utc),
            "jti": str(uuid.uuid4()),
            "type": "access",
            **(extra_data or {}),
        }
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(
        self,
        subject: str,
        access_token_jti: str = None,
        expires_delta: Optional[timedelta] = None,
        extra_data: Dict[str, Any] = None,
    ) -> str:
        """
        創建 JWT 刷新令牌

        參數:
            subject: 令牌主題（通常是用戶 ID）
            access_token_jti: 關聯的訪問令牌 JTI
            expires_delta: 自定義過期時間
            extra_data: 要包含在令牌中的額外數據

        返回:
            編碼的 JWT 刷新令牌
        """
        to_encode = {
            "sub": subject,
            "exp": datetime.now(datetime.timezone.utc)
            + (expires_delta or self.refresh_token_expire),
            "iat": datetime.now(datetime.timezone.utc),
            "jti": str(uuid.uuid4()),
            "type": "refresh",
            **(extra_data or {}),
        }

        if access_token_jti:
            to_encode["access_jti"] = access_token_jti

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def create_token_pair(
        self, subject: str, scopes: List[str] = None, extra_data: Dict[str, Any] = None
    ) -> Tuple[str, str]:
        """
        創建訪問令牌和刷新令牌對

        參數:
            subject: 令牌主題（通常是用戶 ID）
            scopes: 權限範圍列表
            extra_data: 要包含在令牌中的額外數據

        返回:
            (access_token, refresh_token) 元組
        """
        # 創建訪問令牌
        access_token = self.create_access_token(
            subject=subject, scopes=scopes, extra_data=extra_data
        )

        # 解碼訪問令牌以獲取 JTI
        try:
            payload = jwt.decode(
                access_token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_signature": True},
            )
            access_jti = payload.get("jti")
        except jwt.PyJWTError:
            access_jti = None

        # 創建刷新令牌
        refresh_token = self.create_refresh_token(
            subject=subject, access_token_jti=access_jti, extra_data=extra_data
        )

        return access_token, refresh_token

    def verify_token(self, token: str) -> TokenData:
        """
        驗證 JWT 令牌

        參數:
            token: JWT 令牌

        返回:
            TokenData 對象

        拋出:
            HTTPException: 令牌無效或過期
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_signature": True},
            )
            return TokenData(**payload)
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.PyJWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def refresh_access_token(self, refresh_token: str) -> str:
        """
        使用刷新令牌生成新的訪問令牌

        參數:
            refresh_token: 刷新令牌

        返回:
            新的訪問令牌

        拋出:
            HTTPException: 刷新令牌無效或過期
        """
        try:
            # 驗證刷新令牌
            payload = jwt.decode(
                refresh_token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_signature": True},
            )

            # 檢查令牌類型
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # 創建新的訪問令牌
            subject = payload.get("sub")
            if not subject:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token subject",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # 從刷新令牌中獲取額外數據
            extra_data = {
                k: v
                for k, v in payload.items()
                if k not in ["sub", "exp", "iat", "jti", "type", "access_jti"]
            }

            # 創建新的訪問令牌
            return self.create_access_token(
                subject=subject, scopes=payload.get("scopes", []), extra_data=extra_data
            )

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.PyJWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid refresh token: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def get_current_token(
        self, security_scopes: SecurityScopes, token: str
    ) -> TokenData:
        """
        獲取並驗證當前令牌

        參數:
            security_scopes: FastAPI 安全範圍
            token: JWT 令牌

        返回:
            TokenData 對象

        拋出:
            HTTPException: 認證失敗或權限不足
        """
        if security_scopes.scopes:
            authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
        else:
            authenticate_value = "Bearer"

        try:
            token_data = self.verify_token(token)

            # 檢查令牌類型
            token_type = (
                token_data.extra.get("type") if hasattr(token_data, "extra") else None
            )
            if token_type != "access":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers={"WWW-Authenticate": authenticate_value},
                )

            # 檢查權限範圍
            if security_scopes.scopes and token_data.scopes:
                for scope in security_scopes.scopes:
                    if scope not in token_data.scopes:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Not enough permissions. Required: {security_scopes.scope_str}",
                            headers={"WWW-Authenticate": authenticate_value},
                        )

            return token_data

        except HTTPException as e:
            if self.auto_error:
                raise e
            return None

    def requires_auth(self, scopes: List[str] = None) -> Callable:
        """
        創建一個依賴項，要求有效的認證和可選的權限範圍

        參數:
            scopes: 所需的權限範圍列表

        返回:
            FastAPI 依賴函數
        """
        security_scopes = SecurityScopes(scopes=scopes or [])

        async def dependency():
            token = await self.oauth2_scheme.__call__()
            return await self.get_current_token(security_scopes, token)

        return Depends(dependency)
