import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


class JWTHelper:
    """
    JWT 輔助工具類，用於處理 JWT 令牌的生成和驗證
    """

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        token_expire_minutes: int = 30,
        token_type: str = "Bearer",
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_expire_minutes = token_expire_minutes
        self.token_type = token_type
        self.security = HTTPBearer()

    def create_token(
        self, data: Dict[str, Any], expires_delta: Optional[int] = None
    ) -> str:
        """
        創建 JWT 令牌

        Args:
            data: 要編碼到令牌中的數據
            expires_delta: 令牌過期時間（分鐘），如未指定則使用默認值

        Returns:
            生成的 JWT 令牌
        """
        to_encode = {
            **data,
            "exp": datetime.now(datetime.timezone.utc) + timedelta(
                minutes=expires_delta if expires_delta else self.token_expire_minutes
            ),
        }

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        驗證 JWT 令牌

        Args:
            token: 要驗證的 JWT 令牌

        Returns:
            解碼後的令牌數據

        Raises:
            HTTPException: 當令牌無效或已過期時
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="令牌已過期",
                headers={"WWW-Authenticate": self.token_type},
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="無效的令牌",
                headers={"WWW-Authenticate": self.token_type},
            )

    async def get_token_from_header(
        self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())
    ) -> str:
        """
        從請求頭中提取 JWT 令牌

        Args:
            credentials: HTTP 授權憑證

        Returns:
            JWT 令牌
        """
        return credentials.credentials

    async def get_token_data(
        self, token: str = Depends(get_token_from_header)
    ) -> Dict[str, Any]:
        """
        獲取並驗證令牌數據

        Args:
            token: JWT 令牌

        Returns:
            解碼後的令牌數據
        """
        return self.verify_token(token)

    def get_current_user(self, user_field: str = "sub"):
        """
        返回一個依賴項，用於從令牌中獲取當前用戶

        Args:
            user_field: 用戶標識符在令牌中的字段名

        Returns:
            一個依賴函數，返回當前用戶
        """

        async def _get_current_user(
            token_data: Dict[str, Any] = Depends(self.get_token_data),
        ):
            if user_field not in token_data:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"無法從令牌中獲取用戶信息，缺少 '{user_field}' 字段",
                )
            return token_data[user_field]

        return _get_current_user


class JWTBearer:
    """
    JWT 令牌驗證依賴項
    """

    def __init__(self, jwt_helper: JWTHelper, auto_error: bool = True):
        self.jwt_helper = jwt_helper
        self.auto_error = auto_error
        self.security = HTTPBearer(auto_error=auto_error)

    async def __call__(
        self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())
    ) -> Dict[str, Any]:
        """
        驗證 JWT 令牌並返回解碼後的數據

        Args:
            credentials: HTTP 授權憑證

        Returns:
            解碼後的令牌數據
        """
        if self.auto_error:
            return self.jwt_helper.verify_token(credentials.credentials)

        try:
            return self.jwt_helper.verify_token(credentials.credentials)
        except HTTPException:
            return None
