"""
FastAPI 入口，提供註冊、登入與登出 API。
"""

from __future__ import annotations

import logging
import os
from typing import Dict

import uvicorn
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from auth import (
    AccountAlreadyExistsError,
    AuthenticationError,
    CursorKeyAlreadyExistsError,
    InvalidCredentialsError,
    LoginManager,
)
from common_tasks import CommonTaskService
from database import TokenAlreadyRevokedError, create_database
from general_rules import GeneralRuleService
from repositories import CursorRepositoryService, RepositoryFetchError

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
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "./workspace/auth.db")

db_kwargs: Dict[str, str] = {"db_path": SQLITE_DB_PATH} if DB_BACKEND == "sqlite" else {}
database = create_database(DB_BACKEND, **db_kwargs)
database.initialize()
database.ensure_personalization_schema()

CURSOR_API_BASE_URL = os.getenv("CURSOR_API_BASE_URL", "https://api.cursor.com")
try:
    CURSOR_API_TIMEOUT_SECONDS = float(os.getenv("CURSOR_API_TIMEOUT_SECONDS", "30"))
except ValueError as exc:
    raise ValueError("CURSOR_API_TIMEOUT_SECONDS 必須為數值") from exc
if CURSOR_API_TIMEOUT_SECONDS <= 0:
    raise ValueError("CURSOR_API_TIMEOUT_SECONDS 必須為正數")

try:
    REPOSITORY_CACHE_TTL_MINUTES = int(os.getenv("REPOSITORY_CACHE_TTL_MINUTES", "30"))
except ValueError as exc:
    raise ValueError("REPOSITORY_CACHE_TTL_MINUTES 必須為整數") from exc
if REPOSITORY_CACHE_TTL_MINUTES <= 0:
    raise ValueError("REPOSITORY_CACHE_TTL_MINUTES 必須為正整數")

jwt_secret = os.getenv("JWT_SECRET", "cursor-dev-secret")
jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256")
token_ttl = int(os.getenv("TOKEN_TTL_HOURS", "24"))
login_manager = LoginManager(database, jwt_secret, jwt_algorithm, token_ttl)
repository_service = CursorRepositoryService(
    database,
    base_url=CURSOR_API_BASE_URL,
    http_timeout=CURSOR_API_TIMEOUT_SECONDS,
    cache_ttl_minutes=REPOSITORY_CACHE_TTL_MINUTES,
)
general_rule_service = GeneralRuleService(database)
common_task_service = CommonTaskService(database)


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


class RepositoryItem(BaseModel):
    """單一儲存庫資訊。"""

    owner: str
    name: str
    repository: str


class RepositoryListResponse(BaseModel):
    """取得儲存庫的回應模型。"""

    account: str
    lastSyncedAt: str | None
    repositories: list[RepositoryItem]


class GeneralRuleResponse(BaseModel):
    """取得或更新通用規則的回應模型。"""

    account: str
    repositoryUrl: str
    content: str | None
    lastUpdatedAt: str | None


class GeneralRuleUpdateRequest(BaseModel):
    """更新通用規則的請求模型。"""

    repositoryUrl: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)


class CommonTaskListResponse(BaseModel):
    """取得或更新常用任務的回應模型。"""

    account: str
    repositoryUrl: str
    tasks: list[str]


class CommonTaskUpdateRequest(BaseModel):
    """更新常用任務的請求模型。"""

    repositoryUrl: str = Field(..., min_length=1)
    tasks: list[str] = Field(default_factory=list)


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
    except (AccountAlreadyExistsError, CursorKeyAlreadyExistsError) as exc:
        logger.warning("註冊失敗: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        logger.warning("註冊失敗: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
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


@app.get("/accounts/{account}/repositories", response_model=RepositoryListResponse)
async def list_repositories(account: str) -> RepositoryListResponse:
    """
    依帳號取得可訪問的 Git 儲存庫清單。

    Args:
        account (str): 需要查詢的登入帳號

    Returns:
        RepositoryListResponse: 包含儲存庫列表與最後同步時間

    Examples:
        >>> await list_repositories("demo-account")  # doctest: +SKIP
        RepositoryListResponse(account='demo-account', lastSyncedAt='2024-01-01 00:00:00', repositories=[...])

    Raises:
        HTTPException: 當帳號不存在、輸入為空或遠端呼叫失敗時。
    """
    normalized_account = account.strip()
    if not normalized_account:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="account 不可為空白",
        )

    user = database.get_user_by_account(normalized_account)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="找不到指定帳號",
        )
    try:
        records = repository_service.get_repositories(user.cursor_api_key)
    except RepositoryFetchError as exc:
        logger.error("同步儲存庫失敗: account=%s error=%s", normalized_account, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="無法向 Cursor 取得儲存庫資料",
        ) from exc

    repositories = [
        RepositoryItem(
            owner=record.repository_owner,
            name=record.repository_name,
            repository=record.repository_url,
        )
        for record in records
    ]
    last_synced_at = database.get_latest_repository_created_at(user.cursor_api_key)
    return RepositoryListResponse(
        account=normalized_account,
        lastSyncedAt=last_synced_at,
        repositories=repositories,
    )


@app.get("/accounts/{account}/general-rule", response_model=GeneralRuleResponse)
async def get_general_rule(
    account: str,
    repositoryUrl: str = Query(..., min_length=1),
) -> GeneralRuleResponse:
    """
    取得指定帳號與儲存庫的通用規則。

    Args:
        account (str): 使用者帳號
        repositoryUrl (str): 儲存庫網址

    Returns:
        GeneralRuleResponse: 通用規則內容及最後更新時間

    Examples:
        >>> await get_general_rule("demo", "https://github.com/demo/repo")  # doctest: +SKIP

    Raises:
        HTTPException: 當參數為空或帳號不存在時。
    """
    normalized_account = _normalize_account(account)
    normalized_repo = _normalize_repository_url(repositoryUrl)
    try:
        record = general_rule_service.get_rule_record(normalized_account, normalized_repo)
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    content = record.content if record else None
    last_updated = record.updated_at if record else None
    return GeneralRuleResponse(
        account=normalized_account,
        repositoryUrl=normalized_repo,
        content=content,
        lastUpdatedAt=last_updated,
    )


@app.put("/accounts/{account}/general-rule", response_model=GeneralRuleResponse)
async def upsert_general_rule(account: str, payload: GeneralRuleUpdateRequest) -> GeneralRuleResponse:
    """
    建立或更新指定帳號與儲存庫的通用規則。

    Args:
        account (str): 使用者帳號
        payload (GeneralRuleUpdateRequest): 包含 repositoryUrl 與 content 的請求

    Returns:
        GeneralRuleResponse: 更新後的通用規則

    Examples:
        >>> await upsert_general_rule("demo", GeneralRuleUpdateRequest(repositoryUrl="https://github.com/demo/repo", content="rule"))  # doctest: +SKIP

    Raises:
        HTTPException: 當參數為空或帳號不存在時。
    """
    normalized_account = _normalize_account(account)
    normalized_repo = _normalize_repository_url(payload.repositoryUrl)
    normalized_content = payload.content.strip()
    if not normalized_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="content 不可為空白",
        )
    try:
        general_rule_service.update_rule(normalized_account, normalized_repo, normalized_content)
        record = general_rule_service.get_rule_record(normalized_account, normalized_repo)
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    last_updated = record.updated_at if record else None
    return GeneralRuleResponse(
        account=normalized_account,
        repositoryUrl=normalized_repo,
        content=normalized_content,
        lastUpdatedAt=last_updated,
    )


@app.get("/accounts/{account}/common-tasks", response_model=CommonTaskListResponse)
async def get_common_tasks(
    account: str,
    repositoryUrl: str = Query(..., min_length=1),
) -> CommonTaskListResponse:
    """
    取得指定帳號與儲存庫的常用任務清單。

    Args:
        account (str): 使用者帳號
        repositoryUrl (str): 儲存庫網址

    Returns:
        CommonTaskListResponse: 常用任務內容

    Examples:
        >>> await get_common_tasks("demo", "https://github.com/demo/repo")  # doctest: +SKIP

    Raises:
        HTTPException: 當輸入不合法或帳號不存在時。
    """
    normalized_account = _normalize_account(account)
    normalized_repo = _normalize_repository_url(repositoryUrl)
    try:
        tasks = common_task_service.list_tasks(normalized_account, normalized_repo)
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    return CommonTaskListResponse(
        account=normalized_account,
        repositoryUrl=normalized_repo,
        tasks=tasks,
    )


@app.put("/accounts/{account}/common-tasks", response_model=CommonTaskListResponse)
async def upsert_common_tasks(
    account: str,
    payload: CommonTaskUpdateRequest,
) -> CommonTaskListResponse:
    """
    覆寫指定帳號與儲存庫的常用任務。

    Args:
        account (str): 使用者帳號
        payload (CommonTaskUpdateRequest): 包含 repositoryUrl 與 tasks 的請求

    Returns:
        CommonTaskListResponse: 更新後的常用任務清單

    Examples:
        >>> await upsert_common_tasks("demo", CommonTaskUpdateRequest(repositoryUrl="https://github.com/demo/repo", tasks=["task"]))  # doctest: +SKIP

    Raises:
        HTTPException: 當輸入不合法或帳號不存在時。
    """
    normalized_account = _normalize_account(account)
    normalized_repo = _normalize_repository_url(payload.repositoryUrl)
    try:
        tasks = common_task_service.replace_tasks(normalized_account, normalized_repo, payload.tasks)
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    return CommonTaskListResponse(
        account=normalized_account,
        repositoryUrl=normalized_repo,
        tasks=tasks,
    )


def _normalize_account(account: str) -> str:
    """
    驗證並回傳去除前後空白的帳號字串。

    Args:
        account (str): 原始帳號輸入

    Returns:
        str: 去除空白後的帳號

    Examples:
        >>> _normalize_account(" demo ")
        'demo'

    Raises:
        HTTPException: 當帳號為空時。
    """
    normalized = account.strip()
    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="account 不可為空白",
        )
    return normalized


def _normalize_repository_url(repository_url: str) -> str:
    """
    驗證並回傳去除前後空白的儲存庫網址。

    Args:
        repository_url (str): 原始儲存庫網址

    Returns:
        str: 去除空白後的網址

    Examples:
        >>> _normalize_repository_url(" https://github.com/demo/repo ")
        'https://github.com/demo/repo'

    Raises:
        HTTPException: 當網址為空時。
    """
    normalized = repository_url.strip()
    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="repositoryUrl 不可為空白",
        )
    return normalized


def _http_error_from_value_error(exc: ValueError) -> HTTPException:
    """
    根據 ValueError 內容回傳對應的 HTTPException。

    Args:
        exc (ValueError): 原始錯誤

    Returns:
        HTTPException: 對應的 HTTP 錯誤

    Examples:
        >>> _http_error_from_value_error(ValueError("找不到指定帳號")).status_code
        404

    Raises:
        None.
    """
    detail = str(exc) or "輸入資料不合法"
    status_code = status.HTTP_404_NOT_FOUND if "找不到指定帳號" in detail else status.HTTP_400_BAD_REQUEST
    return HTTPException(status_code=status_code, detail=detail)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))