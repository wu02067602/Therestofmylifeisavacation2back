"""
FastAPI 入口，提供註冊、登入與登出 API。
"""

from __future__ import annotations

import logging
import os
import asyncio
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
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
from task_card import TaskCardService

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


class TaskDescriptionEntryModel(BaseModel):
    """任務描述中的單一項目模型。"""

    type: str = Field(..., min_length=1)
    file_name: str | None = None
    class_name: str | None = None
    responsibility: str | None = None
    notes: str | None = None
    target: str | None = None
    content: str | None = None
    narrative: str | None = None


class TaskCardResponse(BaseModel):
    """任務卡單筆回應模型。"""

    cardId: int
    userId: int
    repositoryUrl: str
    taskName: str
    taskDescription: list[TaskDescriptionEntryModel]
    taskStatus: str
    createdAt: str
    updatedAt: str


class TaskCardListResponse(BaseModel):
    """任務卡列表回應模型。"""

    account: str
    repositoryUrl: str
    cards: list[TaskCardResponse]


class TaskCardCreateRequest(BaseModel):
    """建立任務卡的請求模型。"""

    repositoryUrl: str = Field(..., min_length=1)
    taskName: str = Field(..., min_length=1)
    taskDescription: list[TaskDescriptionEntryModel] = Field(default_factory=list)
    taskStatus: str = Field(..., min_length=1)


class TaskCardUpdateRequest(BaseModel):
    """更新任務卡的請求模型。"""

    repositoryUrl: str = Field(..., min_length=1)
    taskName: str | None = None
    taskDescription: list[TaskDescriptionEntryModel] | None = None
    taskStatus: str | None = None


class TaskCardWebSocketManager:
    """
    管理任務卡通知用的 WebSocket 連線。

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
        初始化 WebSocket 連線管理器。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> TaskCardWebSocketManager()

        Raises:
            None.
        """
        self._connections: dict[str, set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, repository_url: str, websocket: WebSocket) -> None:
        """
        接受新的 WebSocket 連線並加入管理列表。

        Args:
            repository_url (str): 使用者訂閱的儲存庫網址
            websocket (WebSocket): FastAPI WebSocket 實例

        Returns:
            None.

        Examples:
            >>> await manager.connect("https://github.com/demo/repo", websocket)  # doctest: +SKIP

        Raises:
            None.
        """
        await websocket.accept()
        async with self._lock:
            self._connections.setdefault(repository_url, set()).add(websocket)

    async def disconnect(self, repository_url: str, websocket: WebSocket) -> None:
        """
        移除既有的 WebSocket 連線。

        Args:
            repository_url (str): 訂閱的儲存庫網址
            websocket (WebSocket): FastAPI WebSocket 實例

        Returns:
            None.

        Examples:
            >>> await manager.disconnect("https://github.com/demo/repo", websocket)  # doctest: +SKIP

        Raises:
            None.
        """
        async with self._lock:
            connections = self._connections.get(repository_url)
            if not connections:
                return
            connections.discard(websocket)
            if not connections:
                self._connections.pop(repository_url, None)

    async def broadcast(self, repository_url: str, payload: dict[str, Any]) -> None:
        """
        將事件廣播給訂閱指定儲存庫的所有連線。

        Args:
            repository_url (str): 訂閱的儲存庫網址
            payload (dict[str, Any]): 要廣播的事件資料

        Returns:
            None.

        Examples:
            >>> await manager.broadcast("https://github.com/demo/repo", {"event": "updated"})  # doctest: +SKIP

        Raises:
            None.
        """
        async with self._lock:
            targets = list(self._connections.get(repository_url, set()))
        for connection in targets:
            try:
                await connection.send_json(payload)
            except (RuntimeError, WebSocketDisconnect):
                await self.disconnect(repository_url, connection)


task_card_socket_manager = TaskCardWebSocketManager()


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
    repositoryUrl: str = Query(..., min_length=1),
) -> TaskCardListResponse:
    """
    取得指定帳號與儲存庫的任務卡清單。

    Args:
        account (str): 使用者帳號
        repositoryUrl (str): 儲存庫網址

    Returns:
        TaskCardListResponse: 任務卡資料列表

    Examples:
        >>> await list_task_cards("demo", "https://github.com/demo/repo")  # doctest: +SKIP

    Raises:
        HTTPException: 當輸入不合法或找不到使用者時。
    """
    normalized_account = _normalize_account(account)
    normalized_repo = _normalize_repository_url(repositoryUrl)
    try:
        cards = task_card_service.list_cards(normalized_account, normalized_repo)
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    response_cards = [_to_task_card_response(card) for card in cards]
    return TaskCardListResponse(
        account=normalized_account,
        repositoryUrl=normalized_repo,
        cards=response_cards,
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
        payload (TaskCardCreateRequest): 包含任務卡內容的請求

    Returns:
        TaskCardResponse: 新建立的任務卡

    Examples:
        >>> await create_task_card("demo", TaskCardCreateRequest(...))  # doctest: +SKIP

    Raises:
        HTTPException: 當輸入驗證失敗或找不到使用者時。
    """
    normalized_account = _normalize_account(account)
    normalized_repo = _normalize_repository_url(payload.repositoryUrl)
    description_entries = _convert_description_models(payload.taskDescription)
    try:
        card = task_card_service.create_card(
            normalized_account,
            normalized_repo,
            payload.taskName,
            description_entries,
            payload.taskStatus,
        )
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    response_card = _to_task_card_response(card)
    await _broadcast_task_card_event(normalized_repo, "task_card_created", response_card)
    return response_card


@app.put("/accounts/{account}/task-cards/{card_id}", response_model=TaskCardResponse)
async def update_task_card(
    account: str,
    card_id: int,
    payload: TaskCardUpdateRequest,
) -> TaskCardResponse:
    """
    更新指定的任務卡。

    Args:
        account (str): 使用者帳號
        card_id (int): 任務卡識別碼
        payload (TaskCardUpdateRequest): 要更新的欄位

    Returns:
        TaskCardResponse: 更新後的任務卡

    Examples:
        >>> await update_task_card("demo", 1, TaskCardUpdateRequest(repositoryUrl="https://github.com/demo/repo", taskStatus="Done"))  # doctest: +SKIP

    Raises:
        HTTPException: 當輸入驗證失敗或找不到資料時。
    """
    normalized_account = _normalize_account(account)
    normalized_repo = _normalize_repository_url(payload.repositoryUrl)
    description_entries = (
        _convert_description_models(payload.taskDescription) if payload.taskDescription is not None else None
    )
    try:
        card = task_card_service.update_card(
            normalized_account,
            normalized_repo,
            card_id,
            task_name=payload.taskName,
            task_description=description_entries,
            task_status=payload.taskStatus,
        )
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    response_card = _to_task_card_response(card)
    await _broadcast_task_card_event(normalized_repo, "task_card_updated", response_card)
    return response_card


@app.delete("/accounts/{account}/task-cards/{card_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_task_card(
    account: str,
    card_id: int,
    repositoryUrl: str = Query(..., min_length=1),
) -> None:
    """
    刪除指定任務卡。

    Args:
        account (str): 使用者帳號
        card_id (int): 任務卡識別碼
        repositoryUrl (str): 任務卡所屬儲存庫

    Returns:
        None.

    Examples:
        >>> await delete_task_card("demo", 1, "https://github.com/demo/repo")  # doctest: +SKIP

    Raises:
        HTTPException: 當輸入驗證失敗或任務卡不存在時。
    """
    normalized_account = _normalize_account(account)
    normalized_repo = _normalize_repository_url(repositoryUrl)
    try:
        task_card_service.delete_card(normalized_account, normalized_repo, card_id)
    except ValueError as exc:
        raise _http_error_from_value_error(exc) from exc
    await _broadcast_task_card_event(normalized_repo, "task_card_deleted", None, card_id=card_id)


@app.websocket("/ws/task-cards")
async def task_card_updates(websocket: WebSocket) -> None:
    """
    任務卡即時通知的 WebSocket 端點。

    Args:
        websocket (WebSocket): FastAPI 提供的 WebSocket 物件

    Returns:
        None.

    Examples:
        >>> await task_card_updates(websocket)  # doctest: +SKIP

    Raises:
        None.
    """
    repository_url = websocket.query_params.get("repositoryUrl", "")
    try:
        normalized_repo = _normalize_repository_url(repository_url)
    except HTTPException as exc:
        await websocket.close(code=1008, reason=exc.detail)
        return
    try:
        await task_card_socket_manager.connect(normalized_repo, websocket)
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await task_card_socket_manager.disconnect(normalized_repo, websocket)
    except Exception as exc:  # noqa: BLE001
        logger.error("WebSocket 發生錯誤: repo=%s error=%s", normalized_repo, exc)
        await task_card_socket_manager.disconnect(normalized_repo, websocket)
        await websocket.close(code=1011, reason="internal error")


def _convert_description_models(entries: list[TaskDescriptionEntryModel]) -> list[dict[str, str]]:
    """
    將 Pydantic 模型轉換為任務卡服務可接受的字典列表。

    Args:
        entries (list[TaskDescriptionEntryModel]): 任務描述模型清單

    Returns:
        list[dict[str, str]]: 轉換後的字典清單

    Examples:
        >>> _convert_description_models([])  # doctest: +SKIP
        []

    Raises:
        None.
    """
    return [entry.model_dump(exclude_none=True) for entry in entries]


def _to_task_card_response(card: dict[str, Any]) -> TaskCardResponse:
    """
    將服務層回傳的任務卡字典轉換為回應模型。

    Args:
        card (dict[str, Any]): 任務卡資料字典

    Returns:
        TaskCardResponse: FastAPI 回應模型

    Examples:
        >>> _to_task_card_response({  # doctest: +SKIP
        ...     "card_id": 1,
        ...     "user_id": 2,
        ...     "repository_url": "https://github.com/demo/repo",
        ...     "task_name": "Task",
        ...     "task_description": [],
        ...     "task_status": "ToDo",
        ...     "created_at": "now",
        ...     "updated_at": "now",
        ... })

    Raises:
        None.
    """
    return TaskCardResponse(
        cardId=card["card_id"],
        userId=card["user_id"],
        repositoryUrl=card["repository_url"],
        taskName=card["task_name"],
        taskDescription=card["task_description"],
        taskStatus=card["task_status"],
        createdAt=card["created_at"],
        updatedAt=card["updated_at"],
    )


async def _broadcast_task_card_event(
    repository_url: str,
    event: str,
    card: TaskCardResponse | None,
    card_id: int | None = None,
) -> None:
    """
    透過 WebSocket 將任務卡事件廣播給所有連線。

    Args:
        repository_url (str): 任務卡所屬儲存庫
        event (str): 事件識別，如 task_card_updated
        card (TaskCardResponse | None): 任務卡資料
        card_id (int | None): 任務卡識別碼

    Returns:
        None.

    Examples:
        >>> await _broadcast_task_card_event("https://github.com/demo/repo", "task_card_updated", None)  # doctest: +SKIP

    Raises:
        None.
    """
    payload = {
        "event": event,
        "repositoryUrl": repository_url,
        "card": card.model_dump() if card else None,
        "cardId": card.cardId if card else card_id,
    }
    await task_card_socket_manager.broadcast(repository_url, payload)

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