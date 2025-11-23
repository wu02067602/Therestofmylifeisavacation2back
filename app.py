"""
FastAPI 入口，提供註冊、登入與登出 API。
"""

from __future__ import annotations

import logging
import os
from typing import Dict

import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from auth import (
    AccountAlreadyExistsError,
    AuthenticationError,
    CursorKeyAlreadyExistsError,
    InvalidCredentialsError,
    LoginManager,
)
from database import TokenAlreadyRevokedError, create_database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_BACKEND = os.getenv("DB_BACKEND", "sqlite")
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "/workspace/auth.db")

db_kwargs: Dict[str, str] = {"db_path": SQLITE_DB_PATH} if DB_BACKEND == "sqlite" else {}
database = create_database(DB_BACKEND, **db_kwargs)
database.initialize()

jwt_secret = os.getenv("JWT_SECRET", "cursor-dev-secret")
jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256")
token_ttl = int(os.getenv("TOKEN_TTL_HOURS", "24"))
login_manager = LoginManager(database, jwt_secret, jwt_algorithm, token_ttl)


class RegisterRequest(BaseModel):
    """註冊請求模型。"""

    account: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    cursor_api_key: str = Field(..., min_length=1)


class RegisterResponse(BaseModel):
    """註冊成功回應。"""

    success: bool = True
    message: str = "註冊成功"


class LoginRequest(BaseModel):
    """登入請求模型。"""

    account: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    """登入回應模型。"""

    accessToken: str
    username: str
    userId: int


class LogoutRequest(BaseModel):
    """登出請求模型。"""

    accessToken: str = Field(..., min_length=1)


class LogoutResponse(BaseModel):
    """登出回應模型。"""

    success: bool
    message: str


@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest) -> RegisterResponse:
    """
    處理註冊請求。

    Args:
        payload (RegisterRequest): 包含 account、password、cursor_api_key 的請求模型

    Returns:
        RegisterResponse: 註冊成功訊息

    Examples:
        >>> await register(RegisterRequest(account="demo", password="pwd", cursor_api_key="key"))  # doctest: +SKIP
        RegisterResponse(success=True, message='註冊成功')

    Raises:
        HTTPException: 帳號、Key 重複或驗證失敗時。
    """
    try:
        login_manager.register_user(
            payload.account.strip(),
            payload.password.strip(),
            payload.cursor_api_key.strip(),
        )
    except ValueError as exc:
        logger.warning("註冊失敗: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except (AccountAlreadyExistsError, CursorKeyAlreadyExistsError) as exc:
        logger.warning("註冊失敗: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return RegisterResponse()


@app.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest) -> LoginResponse:
    """
    處理登入請求並返回 JWT。

    Args:
        payload (LoginRequest): 包含 account 與 password 的請求模型

    Returns:
        LoginResponse: 包含 accessToken、username、userId

    Examples:
        >>> await login(LoginRequest(account="demo", password="pwd"))  # doctest: +SKIP
        LoginResponse(accessToken='jwt', username='demo', userId=1)

    Raises:
        HTTPException: 資料驗證或帳密錯誤時。
    """
    try:
        result = login_manager.login(payload.account.strip(), payload.password.strip())
    except (InvalidCredentialsError, ValueError) as exc:
        logger.warning("登入失敗: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc
    return LoginResponse(**result)


@app.post("/logout", response_model=LogoutResponse)
async def logout(payload: LogoutRequest) -> LogoutResponse:
    """
    處理登出請求並註銷 Token。

    Args:
        payload (LogoutRequest): 含 accessToken 的請求模型

    Returns:
        LogoutResponse: 表示登出成功的訊息

    Examples:
        >>> await logout(LogoutRequest(accessToken="token"))  # doctest: +SKIP
        LogoutResponse(success=True, message='登出成功')

    Raises:
        HTTPException: Token 驗證或註銷失敗時。
    """
    try:
        login_manager.logout(payload.accessToken)
    except ValueError as exc:
        logger.warning("登出失敗: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except TokenAlreadyRevokedError as exc:
        logger.warning("Token 已註銷: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except AuthenticationError as exc:
        logger.warning("Token 驗證失敗: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    return LogoutResponse(success=True, message="登出成功")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))