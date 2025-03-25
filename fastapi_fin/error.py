from fastapi import HTTPException, status

class BadRequestError(HTTPException):
    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)

class UnauthorizedError(HTTPException):
    def __init__(self, detail: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        super().__init__(status_code=status_code, detail=detail)

class PaymentRequiredError(HTTPException):
    def __init__(self, detail: str, status_code: int = status.HTTP_402_PAYMENT_REQUIRED):
        super().__init__(status_code=status_code, detail=detail)

class ForbiddenError(HTTPException):
    def __init__(self, detail: str, status_code: int = status.HTTP_403_FORBIDDEN):
        super().__init__(status_code=status_code, detail=detail)

class NotFoundError(HTTPException):
    def __init__(self, detail: str, status_code: int = status.HTTP_404_NOT_FOUND):
        super().__init__(status_code=status_code, detail=detail)

