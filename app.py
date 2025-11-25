"""
FastAPI 入口，提供註冊、登入、登出與任務卡相關 API。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Annotated, Any, Dict, Literal, Union

import uvicorn
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError

from auth import (
    AccountAlreadyExistsError,
    AuthenticationError,
    CursorKeyAlreadyExistsError,
    InvalidCredentialsError,
    LoginManager,
)
from common_tasks import CommonTaskService
from database import TaskCardRecord, TokenAlreadyRevokedError, create_database
from general_rules import GeneralRuleService
from repositories import CursorRepositoryService, RepositoryFetchError
from task_card import InvalidTaskDescriptionError, TaskCardNotFoundError, TaskCardService

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
database.ensure_task_card_schema()

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
task_card_service = TaskCardService(database)


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


class CodeResponsibilityDescription(BaseModel):
    """任務描述：程式碼職責。"""

    type: Literal["code_responsibility"] = "code_responsibility"
    file_name: str = Field(..., min_length=1)
    class_name: str = Field(..., min_length=1)
    responsibility: str = Field(..., min_length=1)
    notes: str | None = None


class ModificationDescription(BaseModel):
    """任務描述：修改項目。"""

    type: Literal["modification"] = "modification"
    target: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)


class ReadingDescription(BaseModel):
    """任務描述：閱讀項目。"""

    type: Literal["reading"] = "reading"
    target: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)


class CustomDescription(BaseModel):
    """任務描述：自訂敘述。"""

    type: Literal["custom"] = "custom"
    narrative: str = Field(..., min_length=1)


TaskDescriptionItem = Annotated[
    Union[
        CodeResponsibilityDescription,
        ModificationDescription,
        ReadingDescription,
        CustomDescription,
    ],
    Field(discriminator="type"),
]


class TaskCardResponse(BaseModel):
    """任務卡回應模型。"""

    cardId: int
    repositoryUrl: str
    taskName: str
    taskDescription: list[dict[str, Any]]
    taskStatus: Literal["ToDo", "InProgress", "Done"]
    createdAt: str
    updatedAt: str


class TaskCardListResponse(BaseModel):
    """任務卡列表回應。"""

    account: str
    repositoryUrl: str | None
    taskCards: list[TaskCardResponse]


class TaskCardCreateRequest(BaseModel):
    """建立任務卡的請求模型。"""

    repositoryUrl: str = Field(..., min_length=1)
    taskName: str = Field(..., min_length=1)
    taskDescription: list[TaskDescriptionItem] = Field(default_factory=list)
    taskStatus: Literal["ToDo", "InProgress", "Done"]


class TaskCardUpdateRequest(BaseModel):
    """更新任務卡的請求模型。"""

    repositoryUrl: str | None = Field(default=None, min_length=1)
    taskName: str | None = Field(default=None, min_length=1)
    taskDescription: list[TaskDescriptionItem] | None = None
    taskStatus: Literal["ToDo", "InProgress", "Done"] | None = None


class TaskCardDeleteResponse(BaseModel):
    """刪除任務卡的回應模型。"""

    success: bool = True


class TaskCardWebSocketManager:
    """
    管理任務卡 WebSocket 連線並提供廣播能力。

    Args:
        None.

    Returns:
        None.

    Examples:
        >>> manager = TaskCardWebSocketManager()

    Raises:
        None.
    """

    def __init__(self) -> None:
        """
        初始化 TaskCardWebSocketManager。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> TaskCardWebSocketManager()

        Raises:
            None.
        """
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """
        接受新的 WebSocket 連線並加入連線池。

        Args:
            websocket (WebSocket): FastAPI WebSocket 物件

        Returns:
            None.

        Examples:
            >>> await manager.connect(ws)  # doctest: +SKIP

        Raises:
            None.
        """
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        """
        從連線池中移除指定 WebSocket。

        Args:
            websocket (WebSocket): FastAPI WebSocket 物件

        Returns:
            None.

        Examples:
            >>> await manager.disconnect(ws)  # doctest: +SKIP

        Raises:
            None.
        """
        async with self._lock:
            self._connections.discard(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """
        將訊息廣播給所有連線中的 WebSocket。

        Args:
            message (dict[str, Any]): 要傳送的 JSON 訊息

        Returns:
            None.

        Examples:
            >>> await manager.broadcast({"event": "task_card.updated"})  # doctest: +SKIP

        Raises:
            None.
        """
        async with self._lock:
            targets = list(self._connections)
        for websocket in targets:
            try:
                await websocket.send_json(message)
            except (WebSocketDisconnect, RuntimeError, ConnectionClosedOK, ConnectionClosedError) as e:
                logger.debug(f"WebSocket 連接已關閉，移除連線: {type(e).__name__}")
                await self.disconnect(websocket)


task_card_ws_manager = TaskCardWebSocketManager()


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


@app.get("/accounts/{account}/task-cards", response_model=TaskCardListResponse)
async def list_task_cards(
    account: str,
    repositoryUrl: str | None = Query(default=None, min_length=1),
) -> TaskCardListResponse:
    """
    取得指定帳號的任務卡列表。

    Args:
        account (str): 使用者帳號
        repositoryUrl (str | None): 儲存庫網址，可為 None 表示全部

    Returns:
        TaskCardListResponse: 任務卡列表

    Examples:
        >>> await list_task_cards("demo")  # doctest: +SKIP

    Raises:
        HTTPException: 當輸入不合法或帳號不存在時。
    """
    normalized_account = _normalize_account(account)
    normalized_repo = None
    if repositoryUrl is not None:
        normalized_repo = _normalize_repository_url(repositoryUrl)
    try:
        records = task_card_service.list_cards(normalized_account, normalized_repo)
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    cards = [_build_task_card_response(record) for record in records]
    return TaskCardListResponse(
        account=normalized_account,
        repositoryUrl=normalized_repo,
        taskCards=cards,
    )


@app.post(
    "/accounts/{account}/task-cards",
    response_model=TaskCardResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_task_card(account: str, payload: TaskCardCreateRequest) -> TaskCardResponse:
    """
    建立新的任務卡。

    Args:
        account (str): 使用者帳號
        payload (TaskCardCreateRequest): 任務卡建立資料

    Returns:
        TaskCardResponse: 新建立的任務卡

    Examples:
        >>> await create_task_card("demo", TaskCardCreateRequest(...))  # doctest: +SKIP

    Raises:
        HTTPException: 當輸入不合法或帳號不存在時。
    """
    normalized_account = _normalize_account(account)
    try:
        record = task_card_service.create_card(
            normalized_account,
            payload.repositoryUrl,
            payload.taskName,
            [item.model_dump() for item in payload.taskDescription],
            payload.taskStatus,
        )
    except InvalidTaskDescriptionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    response = _build_task_card_response(record)
    await _notify_task_card_event("task_card.created", normalized_account, response.model_dump())
    return response


@app.put("/accounts/{account}/task-cards/{card_id}", response_model=TaskCardResponse)
async def update_task_card(
    account: str,
    card_id: int,
    payload: TaskCardUpdateRequest,
) -> TaskCardResponse:
    """
    更新指定任務卡。

    Args:
        account (str): 使用者帳號
        card_id (int): 任務卡主鍵
        payload (TaskCardUpdateRequest): 更新內容

    Returns:
        TaskCardResponse: 更新後的任務卡

    Examples:
        >>> await update_task_card("demo", 1, TaskCardUpdateRequest(taskStatus="Done"))  # doctest: +SKIP

    Raises:
        HTTPException: 當輸入不合法、任務卡不存在或帳號不存在時。
    """
    normalized_account = _normalize_account(account)
    if all(
        value is None
        for value in (
            payload.repositoryUrl,
            payload.taskName,
            payload.taskDescription,
            payload.taskStatus,
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="請至少提供一個可更新欄位",
        )
    description_payload = None
    if payload.taskDescription is not None:
        description_payload = [item.model_dump() for item in payload.taskDescription]
    try:
        record = task_card_service.update_card(
            normalized_account,
            card_id,
            repository_url=payload.repositoryUrl,
            task_name=payload.taskName,
            task_description=description_payload,
            task_status=payload.taskStatus,
        )
    except InvalidTaskDescriptionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except TaskCardNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    response = _build_task_card_response(record)
    await _notify_task_card_event("task_card.updated", normalized_account, response.model_dump())
    return response


@app.delete("/accounts/{account}/task-cards/{card_id}", response_model=TaskCardDeleteResponse)
async def delete_task_card(account: str, card_id: int) -> TaskCardDeleteResponse:
    """
    刪除指定任務卡。

    Args:
        account (str): 使用者帳號
        card_id (int): 任務卡主鍵

    Returns:
        TaskCardDeleteResponse: 刪除結果

    Examples:
        >>> await delete_task_card("demo", 1)  # doctest: +SKIP

    Raises:
        HTTPException: 當輸入不合法或任務卡不存在時。
    """
    normalized_account = _normalize_account(account)
    try:
        record = task_card_service.delete_card(normalized_account, card_id)
    except TaskCardNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    await _notify_task_card_event(
        "task_card.deleted",
        normalized_account,
        {
            "cardId": record.card_id,
            "repositoryUrl": record.repository_url,
        },
    )
    return TaskCardDeleteResponse()


@app.websocket("/ws/task-cards")
async def task_card_ws_endpoint(websocket: WebSocket) -> None:
    """
    提供任務卡事件的 WebSocket 連線。

    Args:
        websocket (WebSocket): FastAPI WebSocket 實例

    Returns:
        None.

    Examples:
        >>> await task_card_ws_endpoint(websocket)  # doctest: +SKIP

    Raises:
        None.
    """
    await task_card_ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await task_card_ws_manager.disconnect(websocket)
    except RuntimeError:
        logger.exception("任務卡 WebSocket 發生例外")
        await task_card_ws_manager.disconnect(websocket)


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


def _build_task_card_response(record: TaskCardRecord) -> TaskCardResponse:
    """
    將資料庫任務卡記錄轉換為回應模型。

    Args:
        record (TaskCardRecord): 任務卡資料列

    Returns:
        TaskCardResponse: 回應模型

    Examples:
        >>> _build_task_card_response(TaskCardRecord(1, 1, "url", "name", "[]", "ToDo", "c", "u"))  # doctest: +SKIP

    Raises:
        None.
    """
    description = _parse_task_description(record.task_description)
    return TaskCardResponse(
        cardId=record.card_id,
        repositoryUrl=record.repository_url,
        taskName=record.task_name,
        taskDescription=description,
        taskStatus=record.task_status,
        createdAt=record.created_at,
        updatedAt=record.updated_at,
    )


def _parse_task_description(raw_description: str) -> list[dict[str, Any]]:
    """
    將資料庫中的任務描述 JSON 轉換為物件列表。

    Args:
        raw_description (str): JSON 字串

    Returns:
        list[dict[str, Any]]: 正常化後的描述物件

    Examples:
        >>> _parse_task_description("[]")
        []

    Raises:
        None.
    """
    try:
        parsed = json.loads(raw_description)
    except (TypeError, ValueError):
        logger.warning("任務卡描述解析失敗，回傳空列表")
        return []
    if not isinstance(parsed, list):
        logger.warning("任務卡描述需為陣列，實際型態為 %s", type(parsed))
        return []
    normalized: list[dict[str, Any]] = []
    for item in parsed:
        if isinstance(item, dict):
            normalized.append(item)
    return normalized


async def _notify_task_card_event(event: str, account: str, card: dict[str, Any]) -> None:
    """
    將任務卡事件透過 WebSocket 廣播給所有連線。

    Args:
        event (str): 事件名稱
        account (str): 相關帳號
        card (dict[str, Any]): 任務卡內容

    Returns:
        None.

    Examples:
        >>> await _notify_task_card_event("task_card.updated", "demo", TaskCardResponse(...))  # doctest: +SKIP

    Raises:
        None.
    """
    await task_card_ws_manager.broadcast(
        {
            "event": event,
            "account": account,
            "card": card,
        }
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))