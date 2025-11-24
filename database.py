"""
資料庫協調層，提供 BigQuery 與 SQLite 的統一存取介面。
"""

from __future__ import annotations

import logging
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class UserRecord:
    """
    代表登入使用者的資料列。

    Args:
        user_id (int): 使用者流水號
        account (str): 使用者帳號
        password (str): 雜湊後的密碼
        cursor_api_key (str): Cursor API Key
        created_at (str): 建立時間戳
        updated_at (str): 更新時間戳

    Returns:
        UserRecord: 使用者資料實體

    Examples:
        >>> UserRecord(1, "demo", "hashed", "ck", "2023-01-01", "2023-01-02")
        UserRecord(user_id=1, account='demo', password='hashed', cursor_api_key='ck', created_at='2023-01-01', updated_at='2023-01-02')

    Raises:
        None.
    """
    user_id: int
    account: str
    password: str
    cursor_api_key: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class RepositoryRecord:
    """
    代表 repositories 資料表中的單一資料列。

    Args:
        repository_id (int): 自動遞增的主鍵
        cursor_api_key (str): 對應的 Cursor API Key
        repository_owner (str): GitHub 擁有者
        repository_name (str): GitHub 儲存庫名稱
        repository_url (str): 儲存庫完整網址
        created_at (str): 建立時間戳

    Returns:
        RepositoryRecord: 儲存庫資料列的不可變實體

    Examples:
        >>> RepositoryRecord(1, "ck", "cursor", "repo", "https://github.com/cursor/repo", "2023-01-01 00:00:00")
        RepositoryRecord(repository_id=1, cursor_api_key='ck', repository_owner='cursor', repository_name='repo', repository_url='https://github.com/cursor/repo', created_at='2023-01-01 00:00:00')

    Raises:
        None.
    """

    repository_id: int
    cursor_api_key: str
    repository_owner: str
    repository_name: str
    repository_url: str
    created_at: str


@dataclass(frozen=True)
class RepositoryPayload:
    """
    代表欲寫入 repositories 資料表的輸入資料。

    Args:
        repository_owner (str): GitHub 擁有者
        repository_name (str): 儲存庫名稱
        repository_url (str): 儲存庫完整網址

    Returns:
        RepositoryPayload: 輸入資料的不可變實體

    Examples:
        >>> RepositoryPayload("cursor", "repo", "https://github.com/cursor/repo")
        RepositoryPayload(repository_owner='cursor', repository_name='repo', repository_url='https://github.com/cursor/repo')

    Raises:
        None.
    """

    repository_owner: str
    repository_name: str
    repository_url: str


@dataclass(frozen=True)
class GeneralRuleRecord:
    """
    代表 general_rules 資料表中的資料列。

    Args:
        user_id (int): 對應 login_users 的 user_id
        repository_url (str): 儲存庫網址
        content (str): 通用規則內容
        updated_at (str): 最後更新時間

    Returns:
        GeneralRuleRecord: 通用規則資料實體

    Examples:
        >>> GeneralRuleRecord(1, "https://github.com/demo/repo", "rule", "2025-01-01 00:00:00")
        GeneralRuleRecord(user_id=1, repository_url='https://github.com/demo/repo', content='rule', updated_at='2025-01-01 00:00:00')

    Raises:
        None.
    """

    user_id: int
    repository_url: str
    content: str
    updated_at: str


@dataclass(frozen=True)
class CommonTaskRecord:
    """
    代表 common_tasks 資料表中的資料列。

    Args:
        task_id (int): 自動遞增的任務識別值
        user_id (int): login_users.user_id
        repository_url (str): 儲存庫網址
        content (str): 任務內容
        updated_at (str): 最後更新時間

    Returns:
        CommonTaskRecord: 常用任務資料實體

    Examples:
        >>> CommonTaskRecord(1, 2, "https://github.com/demo/repo", "task", "2025-01-01 00:00:00")
        CommonTaskRecord(task_id=1, user_id=2, repository_url='https://github.com/demo/repo', content='task', updated_at='2025-01-01 00:00:00')

    Raises:
        None.
    """

    task_id: int
    user_id: int
    repository_url: str
    content: str
    updated_at: str


@dataclass(frozen=True)
class TaskCardRecord:
    """
    代表 task_cards 資料表的資料列。

    Args:
        card_id (int): 任務卡自動遞增識別碼
        user_id (int): login_users.user_id
        repository_url (str): 目標儲存庫網址
        task_name (str): 任務卡顯示名稱
        task_description (str): JSON 格式字串內容
        task_status (str): 任務狀態（例如 ToDo、InProgress、Done）
        created_at (str): 建立時間戳
        updated_at (str): 最後更新時間戳

    Returns:
        TaskCardRecord: 任務卡資料列實體

    Examples:
        >>> TaskCardRecord(
        ...     1,
        ...     2,
        ...     "https://github.com/demo/repo",
        ...     "Implement feature X",
        ...     "[]",
        ...     "ToDo",
        ...     "2025-01-01 00:00:00",
        ...     "2025-01-01 00:00:00",
        ... )
        TaskCardRecord(card_id=1, user_id=2, repository_url='https://github.com/demo/repo', task_name='Implement feature X', task_description='[]', task_status='ToDo', created_at='2025-01-01 00:00:00', updated_at='2025-01-01 00:00:00')

    Raises:
        None.
    """

    card_id: int
    user_id: int
    repository_url: str
    task_name: str
    task_description: str
    task_status: str
    created_at: str
    updated_at: str


class DatabaseError(RuntimeError):
    """
    所有資料庫相關錯誤的基底類別。

    Args:
        message (str): 錯誤訊息

    Returns:
        None.

    Examples:
        >>> raise DatabaseError("資料庫錯誤")
        Traceback (most recent call last):
        ...
        DatabaseError: 資料庫錯誤

    Raises:
        None.
    """


class DatabaseInitializationError(DatabaseError):
    """
    初始化資料庫時發生的錯誤。

    Args:
        message (str): 具體錯誤說明

    Returns:
        None.

    Examples:
        >>> raise DatabaseInitializationError("初始化失敗")
        Traceback (most recent call last):
        ...
        DatabaseInitializationError: 初始化失敗

    Raises:
        None.
    """


class TokenAlreadyRevokedError(DatabaseError):
    """
    嘗試註銷已註銷的 Token 時拋出的錯誤。

    Args:
        message (str): 錯誤訊息

    Returns:
        None.

    Examples:
        >>> raise TokenAlreadyRevokedError("token 已被註銷")
        Traceback (most recent call last):
        ...
        TokenAlreadyRevokedError: token 已被註銷

    Raises:
        None.
    """


class DatabaseGateway(ABC):
    """
    定義多種資料庫實作需遵循的協調介面。

    Args:
        None.

    Returns:
        None.

    Examples:
        >>> isinstance(SQLiteDatabase("auth.db"), DatabaseGateway)
        True

    Raises:
        None.
    """

    @abstractmethod
    def initialize(self) -> None:
        """
        建立必要表格與觸發器。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> db = SQLiteDatabase("auth.db")
            >>> db.initialize()

        Raises:
            DatabaseInitializationError: 初始化發生錯誤時。
        """

    @abstractmethod
    def create_user(self, account: str, password: str, cursor_api_key: str) -> UserRecord:
        """
        建立新的登入使用者。

        Args:
            account (str): 帳號
            password (str): 雜湊後密碼
            cursor_api_key (str): Cursor API Key

        Returns:
            UserRecord: 新建立的使用者資料

        Examples:
            >>> db = SQLiteDatabase("auth.db")
            >>> db.initialize()
            >>> db.create_user("foo", "hashed", "key")
            UserRecord(...)

        Raises:
            DatabaseError: 當插入資料失敗時。
        """

    @abstractmethod
    def get_user_by_account(self, account: str) -> Optional[UserRecord]:
        """
        依帳號尋找使用者。

        Args:
            account (str): 帳號

        Returns:
            Optional[UserRecord]: 找到則回傳使用者，否則 None

        Examples:
            >>> db.get_user_by_account("demo")

        Raises:
            DatabaseError: 查詢失敗時。
        """

    @abstractmethod
    def get_user_by_credentials(self, account: str, password: str) -> Optional[UserRecord]:
        """
        依帳號與密碼尋找使用者。

        Args:
            account (str): 帳號
            password (str): 雜湊後密碼

        Returns:
            Optional[UserRecord]: 找到則回傳使用者

        Examples:
            >>> db.get_user_by_credentials("demo", "hashed")

        Raises:
            DatabaseError: 查詢失敗時。
        """

    @abstractmethod
    def get_user_by_cursor_key(self, cursor_api_key: str) -> Optional[UserRecord]:
        """
        依 Cursor API Key 取得使用者。

        Args:
            cursor_api_key (str): Key

        Returns:
            Optional[UserRecord]: 找到則回傳使用者

        Examples:
            >>> db.get_user_by_cursor_key("key")

        Raises:
            DatabaseError: 查詢失敗時。
        """

    @abstractmethod
    def revoke_token(self, access_token: str) -> None:
        """
        註銷 JWT Token。

        Args:
            access_token (str): JWT 字串

        Returns:
            None.

        Examples:
            >>> db.revoke_token("token")

        Raises:
            TokenAlreadyRevokedError: Token 已存在時。
            DatabaseError: 寫入錯誤時。
        """

    @abstractmethod
    def is_token_revoked(self, access_token: str) -> bool:
        """
        檢查 Token 是否已註銷。

        Args:
            access_token (str): JWT 字串

        Returns:
            bool: True 表示已註銷

        Examples:
            >>> db.is_token_revoked("token")
            False

        Raises:
            DatabaseError: 查詢錯誤時。
        """
    @abstractmethod
    def ensure_repository_schema(self) -> None:
        """
        建立 repositories 資料表與必要索引。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> db.ensure_repository_schema()  # doctest: +SKIP

        Raises:
            DatabaseInitializationError: 建立資料表失敗時。
        """

    @abstractmethod
    def ensure_personalization_schema(self) -> None:
        """
        建立通用規則與常用任務相關資料表。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> db.ensure_personalization_schema()  # doctest: +SKIP

        Raises:
            DatabaseInitializationError: 建立資料表失敗時。
        """

    @abstractmethod
    def ensure_task_card_schema(self) -> None:
        """
        建立 task_cards 資料表與索引。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> db.ensure_task_card_schema()  # doctest: +SKIP

        Raises:
            DatabaseInitializationError: 建表失敗時。
        """

    @abstractmethod
    def replace_repositories(
        self,
        cursor_api_key: str,
        repositories: Sequence[RepositoryPayload],
    ) -> list[RepositoryRecord]:
        """
        以覆蓋方式寫入指定 Cursor API Key 的儲存庫。

        Args:
            cursor_api_key (str): Cursor API Key
            repositories (Sequence[RepositoryPayload]): 欲寫入的儲存庫清單

        Returns:
            list[RepositoryRecord]: 實際寫入後的資料列

        Examples:
            >>> db.replace_repositories("ck", [RepositoryPayload("cursor", "repo", "url")])  # doctest: +SKIP

        Raises:
            ValueError: 當 cursor_api_key 為空時。
            DatabaseError: 寫入資料庫失敗時。
        """

    @abstractmethod
    def get_repositories(self, cursor_api_key: str) -> list[RepositoryRecord]:
        """
        取得指定 Cursor API Key 的儲存庫清單。

        Args:
            cursor_api_key (str): Cursor API Key

        Returns:
            list[RepositoryRecord]: 符合條件的儲存庫資料

        Examples:
            >>> db.get_repositories("ck")  # doctest: +SKIP

        Raises:
            ValueError: 當 cursor_api_key 為空時。
            DatabaseError: 查詢資料庫失敗時。
        """

    @abstractmethod
    def create_task_card(
        self,
        user_id: int,
        repository_url: str,
        task_name: str,
        task_description: str,
        task_status: str,
    ) -> TaskCardRecord:
        """
        建立新的 task_card。

        Args:
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址
            task_name (str): 任務名稱
            task_description (str): JSON 字串描述
            task_status (str): 任務狀態

        Returns:
            TaskCardRecord: 實際寫入的任務卡資料

        Examples:
            >>> db.create_task_card(1, "https://github.com/demo/repo", "Task", "[]", "ToDo")  # doctest: +SKIP

        Raises:
            DatabaseError: 寫入資料庫失敗時。
            ValueError: 輸入參數不合法時。
        """

    @abstractmethod
    def list_task_cards(
        self,
        user_id: int,
        repository_url: str,
    ) -> list[TaskCardRecord]:
        """
        取得指定使用者與儲存庫的所有 task_cards。

        Args:
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            list[TaskCardRecord]: 任務卡清單

        Examples:
            >>> db.list_task_cards(1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            DatabaseError: 查詢資料庫失敗時。
            ValueError: 輸入參數不合法時。
        """

    @abstractmethod
    def update_task_card(
        self,
        card_id: int,
        user_id: int,
        repository_url: str,
        task_name: Optional[str] = None,
        task_description: Optional[str] = None,
        task_status: Optional[str] = None,
    ) -> TaskCardRecord:
        """
        更新指定任務卡的內容。

        Args:
            card_id (int): 任務卡識別碼
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址
            task_name (Optional[str]): 新任務名稱
            task_description (Optional[str]): 新任務描述 JSON 字串
            task_status (Optional[str]): 新任務狀態

        Returns:
            TaskCardRecord: 更新後的任務卡資料

        Examples:
            >>> db.update_task_card(1, 1, "https://github.com/demo/repo", task_status="Done")  # doctest: +SKIP

        Raises:
            DatabaseError: 更新資料庫失敗時。
            ValueError: 未提供可更新欄位或輸入不合法時。
        """

    @abstractmethod
    def delete_task_card(
        self,
        card_id: int,
        user_id: int,
        repository_url: str,
    ) -> None:
        """
        刪除指定任務卡。

        Args:
            card_id (int): 任務卡識別碼
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            None.

        Examples:
            >>> db.delete_task_card(1, 1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            DatabaseError: 刪除資料時發生錯誤。
            ValueError: 輸入參數不合法時。
        """

    @abstractmethod
    def get_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> Optional[GeneralRuleRecord]:
        """
        取得指定使用者與儲存庫對應的通用規則。

        Args:
            user_id (int): login_users 的 user_id
            repository_url (str): 儲存庫網址

        Returns:
            Optional[GeneralRuleRecord]: 找到則回傳資料，否則 None

        Examples:
            >>> db.get_general_rule_by_user(1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            ValueError: 當 user_id 或 repository_url 不合法時。
            DatabaseError: 查詢資料庫失敗時。
        """

    @abstractmethod
    def upsert_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
        rule_content: str,
    ) -> GeneralRuleRecord:
        """
        建立或更新指定使用者與儲存庫的通用規則。

        Args:
            user_id (int): login_users 的 user_id
            repository_url (str): 儲存庫網址
            rule_content (str): 通用規則內容

        Returns:
            GeneralRuleRecord: 實際寫入的資料列

        Examples:
            >>> db.upsert_general_rule_by_user(1, "https://github.com/demo/repo", "規則")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入為空時。
            DatabaseError: 寫入資料庫失敗時。
        """

    @abstractmethod
    def list_common_tasks_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> list[CommonTaskRecord]:
        """
        取得指定使用者與儲存庫的常用任務清單。

        Args:
            user_id (int): login_users 的 user_id
            repository_url (str): 儲存庫網址

        Returns:
            list[CommonTaskRecord]: 常用任務資料列

        Examples:
            >>> db.list_common_tasks_by_user(1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入為空時。
            DatabaseError: 查詢資料庫失敗時。
        """

    @abstractmethod
    def replace_common_tasks_by_user(
        self,
        user_id: int,
        repository_url: str,
        tasks: Sequence[str],
    ) -> list[CommonTaskRecord]:
        """
        以覆蓋方式更新指定使用者與儲存庫的常用任務。

        Args:
            user_id (int): login_users 的 user_id
            repository_url (str): 儲存庫網址
            tasks (Sequence[str]): 需要寫入的任務內容

        Returns:
            list[CommonTaskRecord]: 更新後的所有常用任務

        Examples:
            >>> db.replace_common_tasks_by_user(1, "https://github.com/demo/repo", ["task"])  # doctest: +SKIP

        Raises:
            ValueError: 當輸入為空或 user_id 不合法時。
            DatabaseError: 寫入資料庫失敗時。
        """

    @abstractmethod
    def get_latest_repository_created_at(self, cursor_api_key: str) -> Optional[str]:
        """
        取得儲存庫資料的最新建立時間。

        Args:
            cursor_api_key (str): Cursor API Key

        Returns:
            Optional[str]: 若存在資料則回傳最新的 created_at 字串，否則 None

        Examples:
            >>> db.get_latest_repository_created_at("ck")  # doctest: +SKIP

        Raises:
            ValueError: 當 cursor_api_key 為空時。
            DatabaseError: 查詢資料庫失敗時。
        """

def create_database(backend: str, **kwargs) -> DatabaseGateway:
    """
    依資料庫類型建立對應的實作。

    Args:
        backend (str): 'sqlite' 或 'bigquery'
        **kwargs: 資料庫初始化參數

    Returns:
        DatabaseGateway: 對應的資料庫實例

    Examples:
        >>> create_database("sqlite", db_path="auth.db")

    Raises:
        ValueError: 後端類型不支援時。
    """
    normalized_backend = backend.lower().strip()
    if normalized_backend == "sqlite":
        return SQLiteDatabase(kwargs.get("db_path", "auth.db"))
    if normalized_backend == "bigquery":
        return BigQueryDatabase(kwargs)
    raise ValueError(f"Unsupported database backend: {backend}")


class SQLiteDatabase(DatabaseGateway):
    """
    SQLite 的資料庫實作。

    Args:
        db_path (str | Path): SQLite 檔案路徑

    Returns:
        None.

    Examples:
        >>> db = SQLiteDatabase("auth.db")

    Raises:
        ValueError: 路徑為空時。
    """

    def __init__(self, db_path: str | Path):
        """
        初始化 SQLiteDatabase。

        Args:
            db_path (str | Path): SQLite 檔案路徑

        Returns:
            None.

        Examples:
            >>> SQLiteDatabase("/tmp/auth.db")

        Raises:
            ValueError: 當路徑為空字串時。
        """
        if not str(db_path).strip():
            raise ValueError("SQLite db_path 不可為空字串")
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

    def initialize(self) -> None:
        """
        建立需要的資料表與觸發器。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> db = SQLiteDatabase("auth.db")
            >>> db.initialize()

        Raises:
            DatabaseInitializationError: 建表失敗時。
        """
        try:
            with self._connect() as conn:
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.execute("PRAGMA recursive_triggers = OFF;")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS login_users (
                        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        account TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        cursor_api_key TEXT NOT NULL UNIQUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS revoked_tokens (
                        token TEXT PRIMARY KEY,
                        revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS trg_login_users_updated_at
                    AFTER UPDATE ON login_users
                    FOR EACH ROW
                    BEGIN
                        UPDATE login_users
                        SET updated_at = CURRENT_TIMESTAMP
                        WHERE user_id = NEW.user_id;
                    END;
                    """
                )
                self._create_repository_table(conn)
                self._create_personalization_tables(conn)
                self._create_task_card_table(conn)
                conn.commit()
        except sqlite3.Error as exc:
            logger.exception("初始化 SQLite 資料庫失敗: %s", exc)
            raise DatabaseInitializationError("初始化 SQLite 資料庫失敗") from exc

    def ensure_repository_schema(self) -> None:
        """
        確保 repositories 資料表存在。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> db.ensure_repository_schema()  # doctest: +SKIP

        Raises:
            DatabaseInitializationError: 建表失敗時。
        """
        try:
            with self._connect() as conn:
                self._create_repository_table(conn)
                conn.commit()
        except sqlite3.Error as exc:
            logger.exception("建立 repositories 資料表失敗: %s", exc)
            raise DatabaseInitializationError("建立 repositories 資料表失敗") from exc

    def ensure_personalization_schema(self) -> None:
        """
        確保通用規則與常用任務資料表存在。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> db.ensure_personalization_schema()  # doctest: +SKIP

        Raises:
            DatabaseInitializationError: 建立資料表失敗時。
        """
        try:
            with self._connect() as conn:
                self._create_personalization_tables(conn)
                conn.commit()
        except sqlite3.Error as exc:
            logger.exception("建立 personalization 資料表失敗: %s", exc)
            raise DatabaseInitializationError("建立 personalization 資料表失敗") from exc

    def ensure_task_card_schema(self) -> None:
        """
        確保 task_cards 資料表存在。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> db.ensure_task_card_schema()  # doctest: +SKIP

        Raises:
            DatabaseInitializationError: 建表失敗時。
        """
        try:
            with self._connect() as conn:
                self._create_task_card_table(conn)
                conn.commit()
        except sqlite3.Error as exc:
            logger.exception("建立 task_cards 資料表失敗: %s", exc)
            raise DatabaseInitializationError("建立 task_cards 資料表失敗") from exc

    def replace_repositories(
        self,
        cursor_api_key: str,
        repositories: Sequence[RepositoryPayload],
    ) -> list[RepositoryRecord]:
        """
        以刪除後重建的方式覆蓋儲存庫資料。

        Args:
            cursor_api_key (str): Cursor API Key
            repositories (Sequence[RepositoryPayload]): 欲寫入的儲存庫清單

        Returns:
            list[RepositoryRecord]: 寫入後的所有資料列

        Examples:
            >>> db.replace_repositories("ck", [RepositoryPayload("owner", "repo", "url")])  # doctest: +SKIP

        Raises:
            ValueError: cursor_api_key 為空時。
            DatabaseError: 寫入資料庫失敗時。
        """
        if not cursor_api_key:
            raise ValueError("cursor_api_key 不可為空")
        try:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM repositories WHERE cursor_api_key = ?;",
                    (cursor_api_key,),
                )
                for repo in repositories:
                    conn.execute(
                        """
                        INSERT INTO repositories (
                            cursor_api_key,
                            repository_owner,
                            repository_name,
                            repository_url
                        )
                        VALUES (?, ?, ?, ?);
                        """,
                        (
                            cursor_api_key,
                            repo.repository_owner,
                            repo.repository_name,
                            repo.repository_url,
                        ),
                    )
                conn.commit()
                return self._fetch_repositories(conn, cursor_api_key)
        except sqlite3.Error as exc:
            logger.exception("覆寫儲存庫資料失敗: key=%s exc=%s", cursor_api_key, exc)
            raise DatabaseError("覆寫儲存庫資料失敗") from exc

    def get_repositories(self, cursor_api_key: str) -> list[RepositoryRecord]:
        """
        取得指定 Cursor API Key 的儲存庫清單。

        Args:
            cursor_api_key (str): Cursor API Key

        Returns:
            list[RepositoryRecord]: 所有儲存庫資料

        Examples:
            >>> db.get_repositories("ck")  # doctest: +SKIP

        Raises:
            ValueError: cursor_api_key 為空時。
            DatabaseError: 查詢資料庫失敗時。
        """
        if not cursor_api_key:
            raise ValueError("cursor_api_key 不可為空")
        try:
            with self._connect() as conn:
                return self._fetch_repositories(conn, cursor_api_key)
        except sqlite3.Error as exc:
            logger.exception("查詢儲存庫資料失敗: key=%s exc=%s", cursor_api_key, exc)
            raise DatabaseError("查詢儲存庫資料失敗") from exc

    def get_latest_repository_created_at(self, cursor_api_key: str) -> Optional[str]:
        """
        取得儲存庫資料的最新建立時間。

        Args:
            cursor_api_key (str): Cursor API Key

        Returns:
            Optional[str]: 最新 created_at 字串，若無資料則為 None

        Examples:
            >>> db.get_latest_repository_created_at("ck")  # doctest: +SKIP

        Raises:
            ValueError: cursor_api_key 為空時。
            DatabaseError: 查詢資料庫失敗時。
        """
        if not cursor_api_key:
            raise ValueError("cursor_api_key 不可為空")
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    SELECT MAX(created_at) AS last_synced_at
                    FROM repositories
                    WHERE cursor_api_key = ?;
                    """,
                    (cursor_api_key,),
                )
                row = cursor.fetchone()
                return row["last_synced_at"] if row and row["last_synced_at"] else None
        except sqlite3.Error as exc:
            logger.exception("查詢儲存庫時間失敗: key=%s exc=%s", cursor_api_key, exc)
            raise DatabaseError("查詢儲存庫時間失敗") from exc

    def create_task_card(
        self,
        user_id: int,
        repository_url: str,
        task_name: str,
        task_description: str,
        task_status: str,
    ) -> TaskCardRecord:
        """
        建立新的任務卡資料列。

        Args:
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址
            task_name (str): 任務名稱
            task_description (str): JSON 格式描述字串
            task_status (str): 任務狀態

        Returns:
            TaskCardRecord: 刚新增的任務卡資料

        Examples:
            >>> db.create_task_card(1, "https://github.com/demo/repo", "Task", "[]", "ToDo")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入參數為空或不合法時。
            DatabaseError: 建立資料列失敗時。
        """
        self._require_positive_user_id(user_id)
        normalized_url = self._normalize_repository_url(repository_url)
        normalized_name = self._normalize_non_empty_text(task_name, "task_name")
        normalized_description = self._normalize_non_empty_text(
            task_description,
            "task_description",
        )
        normalized_status = self._normalize_non_empty_text(task_status, "task_status")
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO task_cards (
                        user_id,
                        repository_url,
                        task_name,
                        task_description,
                        task_status
                    ) VALUES (?, ?, ?, ?, ?);
                    """,
                    (
                        user_id,
                        normalized_url,
                        normalized_name,
                        normalized_description,
                        normalized_status,
                    ),
                )
                conn.commit()
                record = self._fetch_task_card_by_id(conn, cursor.lastrowid)
                if record is None:
                    raise DatabaseError("無法取得剛建立的任務卡資料")
                return record
        except sqlite3.Error as exc:
            logger.exception("建立任務卡失敗: user_id=%s exc=%s", user_id, exc)
            raise DatabaseError("建立 SQLite 任務卡失敗") from exc

    def list_task_cards(
        self,
        user_id: int,
        repository_url: str,
    ) -> list[TaskCardRecord]:
        """
        取得指定使用者與儲存庫的任務卡清單。

        Args:
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            list[TaskCardRecord]: 任務卡列表

        Examples:
            >>> db.list_task_cards(1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入參數為空或不合法時。
            DatabaseError: 查詢資料庫失敗時。
        """
        self._require_positive_user_id(user_id)
        normalized_url = self._normalize_repository_url(repository_url)
        try:
            with self._connect() as conn:
                return self._fetch_task_cards(conn, user_id, normalized_url)
        except sqlite3.Error as exc:
            logger.exception("查詢任務卡清單失敗: user_id=%s exc=%s", user_id, exc)
            raise DatabaseError("查詢 SQLite 任務卡失敗") from exc

    def update_task_card(
        self,
        card_id: int,
        user_id: int,
        repository_url: str,
        task_name: Optional[str] = None,
        task_description: Optional[str] = None,
        task_status: Optional[str] = None,
    ) -> TaskCardRecord:
        """
        更新指定任務卡的欄位。

        Args:
            card_id (int): 任務卡識別碼
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址
            task_name (Optional[str]): 新任務名稱
            task_description (Optional[str]): 新任務描述 JSON 字串
            task_status (Optional[str]): 新任務狀態

        Returns:
            TaskCardRecord: 更新後的任務卡資料

        Examples:
            >>> db.update_task_card(1, 1, "https://github.com/demo/repo", task_status="Done")  # doctest: +SKIP

        Raises:
            ValueError: 當 card_id 不合法或未指定更新欄位時。
            DatabaseError: 更新資料庫失敗或找不到資料時。
        """
        if card_id <= 0:
            raise ValueError("card_id 必須為正整數")
        self._require_positive_user_id(user_id)
        normalized_url = self._normalize_repository_url(repository_url)
        fields: list[str] = []
        params: list[str] = []
        if task_name is not None:
            fields.append("task_name = ?")
            params.append(self._normalize_non_empty_text(task_name, "task_name"))
        if task_description is not None:
            fields.append("task_description = ?")
            params.append(
                self._normalize_non_empty_text(task_description, "task_description")
            )
        if task_status is not None:
            fields.append("task_status = ?")
            params.append(self._normalize_non_empty_text(task_status, "task_status"))
        if not fields:
            raise ValueError("至少需提供一個可更新欄位")
        set_clause = ", ".join(fields + ["updated_at = CURRENT_TIMESTAMP"])
        params.extend([card_id, user_id, normalized_url])
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    f"""
                    UPDATE task_cards
                    SET {set_clause}
                    WHERE card_id = ? AND user_id = ? AND repository_url = ?;
                    """,
                    params,
                )
                if cursor.rowcount == 0:
                    raise DatabaseError("找不到符合條件的任務卡")
                conn.commit()
                record = self._fetch_task_card_by_id(conn, card_id)
                if record is None:
                    raise DatabaseError("無法取得更新後的任務卡資料")
                return record
        except sqlite3.Error as exc:
            logger.exception("更新任務卡失敗: card_id=%s exc=%s", card_id, exc)
            raise DatabaseError("更新 SQLite 任務卡失敗") from exc

    def delete_task_card(
        self,
        card_id: int,
        user_id: int,
        repository_url: str,
    ) -> None:
        """
        刪除指定任務卡。

        Args:
            card_id (int): 任務卡識別碼
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            None.

        Examples:
            >>> db.delete_task_card(1, 1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入參數不合法時。
            DatabaseError: 刪除資料失敗或找不到資料時。
        """
        if card_id <= 0:
            raise ValueError("card_id 必須為正整數")
        self._require_positive_user_id(user_id)
        normalized_url = self._normalize_repository_url(repository_url)
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    DELETE FROM task_cards
                    WHERE card_id = ? AND user_id = ? AND repository_url = ?;
                    """,
                    (card_id, user_id, normalized_url),
                )
                if cursor.rowcount == 0:
                    raise DatabaseError("找不到符合條件的任務卡")
                conn.commit()
        except sqlite3.Error as exc:
            logger.exception("刪除任務卡失敗: card_id=%s exc=%s", card_id, exc)
            raise DatabaseError("刪除 SQLite 任務卡失敗") from exc

    def get_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> Optional[GeneralRuleRecord]:
        """
        取得指定使用者與儲存庫的通用規則。

        Args:
            user_id (int): login_users 的 user_id
            repository_url (str): 儲存庫網址

        Returns:
            Optional[GeneralRuleRecord]: 若存在則回傳資料，否則 None

        Examples:
            >>> db.get_general_rule_by_user(1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            ValueError: 當 user_id 非正整數或 repository_url 為空時。
            DatabaseError: 查詢資料庫失敗時。
        """
        self._require_positive_user_id(user_id)
        normalized_url = self._normalize_repository_url(repository_url)
        try:
            with self._connect() as conn:
                return self._fetch_general_rule(conn, user_id, normalized_url)
        except sqlite3.Error as exc:
            logger.exception("查詢通用規則失敗: user_id=%s exc=%s", user_id, exc)
            raise DatabaseError("查詢 SQLite 通用規則失敗") from exc

    def upsert_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
        rule_content: str,
    ) -> GeneralRuleRecord:
        """
        新增或更新通用規則。

        Args:
            user_id (int): login_users 的 user_id
            repository_url (str): 儲存庫網址
            rule_content (str): 通用規則內容

        Returns:
            GeneralRuleRecord: 更新後的資料列

        Examples:
            >>> db.upsert_general_rule_by_user(1, "https://github.com/demo/repo", "rule")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入為空時。
            DatabaseError: 寫入資料庫失敗時。
        """
        self._require_positive_user_id(user_id)
        normalized_url = self._normalize_repository_url(repository_url)
        normalized_rule = rule_content.strip()
        if not normalized_rule:
            raise ValueError("rule_content 不可為空白")
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO general_rules (user_id, repository_url, rule_content)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id, repository_url)
                    DO UPDATE SET
                        rule_content = excluded.rule_content,
                        updated_at = CURRENT_TIMESTAMP;
                    """,
                    (user_id, normalized_url, normalized_rule),
                )
                conn.commit()
                record = self._fetch_general_rule(conn, user_id, normalized_url)
                if record is None:
                    raise DatabaseError("無法取得剛更新的通用規則")
                return record
        except sqlite3.Error as exc:
            logger.exception("寫入通用規則失敗: user_id=%s exc=%s", user_id, exc)
            raise DatabaseError("寫入 SQLite 通用規則失敗") from exc

    def list_common_tasks_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> list[CommonTaskRecord]:
        """
        取得指定使用者與儲存庫的常用任務清單。

        Args:
            user_id (int): login_users 的 user_id
            repository_url (str): 儲存庫網址

        Returns:
            list[CommonTaskRecord]: 查詢結果

        Examples:
            >>> db.list_common_tasks_by_user(1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入為空時。
            DatabaseError: 查詢資料庫失敗時。
        """
        self._require_positive_user_id(user_id)
        normalized_url = self._normalize_repository_url(repository_url)
        try:
            with self._connect() as conn:
                return self._fetch_common_tasks(conn, user_id, normalized_url)
        except sqlite3.Error as exc:
            logger.exception("查詢常用任務失敗: user_id=%s exc=%s", user_id, exc)
            raise DatabaseError("查詢 SQLite 常用任務失敗") from exc

    def replace_common_tasks_by_user(
        self,
        user_id: int,
        repository_url: str,
        tasks: Sequence[str],
    ) -> list[CommonTaskRecord]:
        """
        覆蓋指定使用者與儲存庫的常用任務。

        Args:
            user_id (int): login_users 的 user_id
            repository_url (str): 儲存庫網址
            tasks (Sequence[str]): 欲寫入的任務內容

        Returns:
            list[CommonTaskRecord]: 更新後的常用任務

        Examples:
            >>> db.replace_common_tasks_by_user(1, "https://github.com/demo/repo", ["task"])  # doctest: +SKIP

        Raises:
            ValueError: 當輸入為空時。
            DatabaseError: 寫入資料庫失敗時。
        """
        self._require_positive_user_id(user_id)
        normalized_url = self._normalize_repository_url(repository_url)
        normalized_tasks = self._prepare_task_contents(tasks)
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    DELETE FROM common_tasks
                    WHERE user_id = ? AND repository_url = ?;
                    """,
                    (user_id, normalized_url),
                )
                for task in normalized_tasks:
                    conn.execute(
                        """
                        INSERT INTO common_tasks (
                            user_id,
                            repository_url,
                            task_content
                        ) VALUES (?, ?, ?);
                        """,
                        (user_id, normalized_url, task),
                    )
                conn.commit()
                return self._fetch_common_tasks(conn, user_id, normalized_url)
        except sqlite3.Error as exc:
            logger.exception("覆寫常用任務失敗: user_id=%s exc=%s", user_id, exc)
            raise DatabaseError("覆寫 SQLite 常用任務失敗") from exc

    def create_user(self, account: str, password: str, cursor_api_key: str) -> UserRecord:
        """
        在 SQLite 中寫入新的登入使用者。

        Args:
            account (str): 帳號
            password (str): 雜湊後密碼
            cursor_api_key (str): Cursor API Key

        Returns:
            UserRecord: 新使用者資料

        Examples:
            >>> db.create_user("foo", "hashed", "key")

        Raises:
            DatabaseError: 寫入失敗時。
        """
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO login_users (account, password, cursor_api_key)
                    VALUES (?, ?, ?);
                    """,
                    (account, password, cursor_api_key),
                )
                conn.commit()
                return self._fetch_user_by_account(conn, account)
        except sqlite3.Error as exc:
            logger.exception("建立使用者時發生錯誤: account=%s exc=%s", account, exc)
            raise DatabaseError("建立 SQLite 使用者資料失敗") from exc

    def get_user_by_account(self, account: str) -> Optional[UserRecord]:
        """
        依帳號查詢使用者。

        Args:
            account (str): 帳號

        Returns:
            Optional[UserRecord]: 找到則回傳資料

        Examples:
            >>> db.get_user_by_account("foo")

        Raises:
            DatabaseError: 查詢失敗時。
        """
        try:
            with self._connect() as conn:
                return self._fetch_user_by_account(conn, account)
        except sqlite3.Error as exc:
            logger.exception("查詢使用者時發生錯誤: account=%s exc=%s", account, exc)
            raise DatabaseError("查詢 SQLite 使用者資料失敗") from exc

    def get_user_by_credentials(self, account: str, password: str) -> Optional[UserRecord]:
        """
        依帳號與密碼查詢使用者。

        Args:
            account (str): 帳號
            password (str): 雜湊後密碼

        Returns:
            Optional[UserRecord]: 找到則回傳資料

        Examples:
            >>> db.get_user_by_credentials("foo", "hashed")

        Raises:
            DatabaseError: 查詢失敗時。
        """
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    SELECT user_id, account, password, cursor_api_key, created_at, updated_at
                    FROM login_users
                    WHERE account = ? AND password = ?;
                    """,
                    (account, password),
                )
                row = cursor.fetchone()
                return self._row_to_user(row)
        except sqlite3.Error as exc:
            logger.exception("憑證查詢失敗: account=%s exc=%s", account, exc)
            raise DatabaseError("查詢 SQLite 使用者資料失敗") from exc

    def get_user_by_cursor_key(self, cursor_api_key: str) -> Optional[UserRecord]:
        """
        依 Cursor API Key 查詢使用者。

        Args:
            cursor_api_key (str): Key

        Returns:
            Optional[UserRecord]: 找到則回傳資料

        Examples:
            >>> db.get_user_by_cursor_key("key")

        Raises:
            DatabaseError: 查詢失敗時。
        """
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    SELECT user_id, account, password, cursor_api_key, created_at, updated_at
                    FROM login_users
                    WHERE cursor_api_key = ?;
                    """,
                    (cursor_api_key,),
                )
                row = cursor.fetchone()
                return self._row_to_user(row)
        except sqlite3.Error as exc:
            logger.exception("依 Cursor API Key 查詢失敗: key=%s exc=%s", cursor_api_key, exc)
            raise DatabaseError("查詢 SQLite 使用者資料失敗") from exc

    def revoke_token(self, access_token: str) -> None:
        """
        註銷 JWT Token。

        Args:
            access_token (str): JWT 字串

        Returns:
            None.

        Examples:
            >>> db.revoke_token("token")

        Raises:
            TokenAlreadyRevokedError: Token 重複註銷時。
            DatabaseError: 資料庫寫入失敗時。
        """
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "SELECT token FROM revoked_tokens WHERE token = ?;",
                    (access_token,),
                )
                if cursor.fetchone():
                    raise TokenAlreadyRevokedError("Token 已被註銷")
                conn.execute(
                    "INSERT INTO revoked_tokens (token) VALUES (?);",
                    (access_token,),
                )
                conn.commit()
        except TokenAlreadyRevokedError:
            raise
        except sqlite3.Error as exc:
            logger.exception("註銷 Token 失敗: exc=%s", exc)
            raise DatabaseError("註銷 Token 失敗") from exc

    def is_token_revoked(self, access_token: str) -> bool:
        """
        檢查 Token 是否已註銷。

        Args:
            access_token (str): JWT 字串

        Returns:
            bool: True 表示已註銷

        Examples:
            >>> db.is_token_revoked("token")
            False

        Raises:
            DatabaseError: 查詢失敗時。
        """
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "SELECT token FROM revoked_tokens WHERE token = ?;",
                    (access_token,),
                )
                return cursor.fetchone() is not None
        except sqlite3.Error as exc:
            logger.exception("檢查 Token 失敗: exc=%s", exc)
            raise DatabaseError("檢查 Token 失敗") from exc

    def _connect(self) -> sqlite3.Connection:
        """
        取得 SQLite 連線。

        Args:
            None.

        Returns:
            sqlite3.Connection: 可用的連線

        Examples:
            >>> conn = db._connect()

        Raises:
            DatabaseError: 無法建立連線時。
        """
        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as exc:
            logger.exception("無法建立 SQLite 連線: %s", exc)
            raise DatabaseError("無法建立 SQLite 連線") from exc

    def _create_repository_table(self, conn: sqlite3.Connection) -> None:
        """
        在既有連線上建立 repositories 資料表。

        Args:
            conn (sqlite3.Connection): 既有的 SQLite 連線

        Returns:
            None.

        Examples:
            >>> db._create_repository_table(conn)  # doctest: +SKIP

        Raises:
            sqlite3.Error: 建表失敗時。
        """
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS repositories (
                repository_id INTEGER PRIMARY KEY AUTOINCREMENT,
                cursor_api_key TEXT NOT NULL,
                repository_owner TEXT NOT NULL,
                repository_name TEXT NOT NULL,
                repository_url TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cursor_api_key) REFERENCES login_users(cursor_api_key)
                    ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_repositories_cursor_api_key
            ON repositories(cursor_api_key);
            """
        )

    def _fetch_repositories(
        self,
        conn: sqlite3.Connection,
        cursor_api_key: str,
    ) -> list[RepositoryRecord]:
        """
        查詢 repositories 並轉換為 RepositoryRecord。

        Args:
            conn (sqlite3.Connection): 既有的 SQLite 連線
            cursor_api_key (str): Cursor API Key

        Returns:
            list[RepositoryRecord]: 查詢結果清單

        Examples:
            >>> db._fetch_repositories(conn, "ck")  # doctest: +SKIP

        Raises:
            sqlite3.Error: 查詢失敗時。
        """
        cursor = conn.execute(
            """
            SELECT
                repository_id,
                cursor_api_key,
                repository_owner,
                repository_name,
                repository_url,
                created_at
            FROM repositories
            WHERE cursor_api_key = ?
            ORDER BY repository_owner, repository_name;
            """,
            (cursor_api_key,),
        )
        rows = cursor.fetchall()
        return [self._row_to_repository(row) for row in rows]

    def _fetch_user_by_account(self, conn: sqlite3.Connection, account: str) -> Optional[UserRecord]:
        """
        以帳號查詢使用者（共用內部方法）。

        Args:
            conn (sqlite3.Connection): 既有連線
            account (str): 帳號

        Returns:
            Optional[UserRecord]: 找到則回傳資料

        Examples:
            >>> db._fetch_user_by_account(conn, "foo")

        Raises:
            DatabaseError: 查詢失敗時。
        """
        try:
            cursor = conn.execute(
                """
                SELECT user_id, account, password, cursor_api_key, created_at, updated_at
                FROM login_users
                WHERE account = ?;
                """,
                (account,),
            )
            row = cursor.fetchone()
            return self._row_to_user(row)
        except sqlite3.Error as exc:
            logger.exception("內部查詢失敗: account=%s exc=%s", account, exc)
            raise DatabaseError("查詢 SQLite 使用者資料失敗") from exc

    def _row_to_user(self, row: Optional[sqlite3.Row]) -> Optional[UserRecord]:
        """
        將 SQLite 資料列轉換為 UserRecord。

        Args:
            row (Optional[sqlite3.Row]): SQLite 資料列

        Returns:
            Optional[UserRecord]: 對應的資料實體

        Examples:
            >>> db._row_to_user(row)

        Raises:
            None.
        """
        if row is None:
            return None
        return UserRecord(
            user_id=row["user_id"],
            account=row["account"],
            password=row["password"],
            cursor_api_key=row["cursor_api_key"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _row_to_repository(self, row: sqlite3.Row) -> RepositoryRecord:
        """
        將 SQLite 資料列轉換為 RepositoryRecord。

        Args:
            row (sqlite3.Row): SQLite 資料列

        Returns:
            RepositoryRecord: 對應的資料實體

        Examples:
            >>> db._row_to_repository(row)  # doctest: +SKIP

        Raises:
            None.
        """
        return RepositoryRecord(
            repository_id=row["repository_id"],
            cursor_api_key=row["cursor_api_key"],
            repository_owner=row["repository_owner"],
            repository_name=row["repository_name"],
            repository_url=row["repository_url"],
            created_at=row["created_at"],
        )

    def _create_personalization_tables(self, conn: sqlite3.Connection) -> None:
        """
        建立通用規則與常用任務相關資料表。

        Args:
            conn (sqlite3.Connection): 既有 SQLite 連線

        Returns:
            None.

        Examples:
            >>> db._create_personalization_tables(conn)  # doctest: +SKIP

        Raises:
            sqlite3.Error: 建表失敗時。
        """
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS general_rules (
                user_id INTEGER NOT NULL,
                repository_url TEXT NOT NULL,
                rule_content TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, repository_url),
                FOREIGN KEY (user_id) REFERENCES login_users(user_id)
                    ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS common_tasks (
                task_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                repository_url TEXT NOT NULL,
                task_content TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES login_users(user_id)
                    ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_common_tasks_user_repo
            ON common_tasks(user_id, repository_url);
            """
        )

    def _create_task_card_table(self, conn: sqlite3.Connection) -> None:
        """
        建立 task_cards 資料表與索引。

        Args:
            conn (sqlite3.Connection): 既有 SQLite 連線

        Returns:
            None.

        Examples:
            >>> db._create_task_card_table(conn)  # doctest: +SKIP

        Raises:
            sqlite3.Error: 建表或建立索引失敗時。
        """
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS task_cards (
                card_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                repository_url TEXT NOT NULL,
                task_name TEXT NOT NULL,
                task_description TEXT NOT NULL,
                task_status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES login_users(user_id)
                    ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_task_cards_user_repo
            ON task_cards(user_id, repository_url);
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_task_cards_updated_at
            AFTER UPDATE ON task_cards
            FOR EACH ROW
            BEGIN
                UPDATE task_cards
                SET updated_at = CURRENT_TIMESTAMP
                WHERE card_id = NEW.card_id;
            END;
            """
        )

    def _fetch_task_cards(
        self,
        conn: sqlite3.Connection,
        user_id: int,
        repository_url: str,
    ) -> list[TaskCardRecord]:
        """
        取得指定使用者與儲存庫的任務卡清單。

        Args:
            conn (sqlite3.Connection): 既有 SQLite 連線
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            list[TaskCardRecord]: 查詢結果列表

        Examples:
            >>> db._fetch_task_cards(conn, 1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            sqlite3.Error: 查詢資料庫失敗時。
        """
        cursor = conn.execute(
            """
            SELECT
                card_id,
                user_id,
                repository_url,
                task_name,
                task_description,
                task_status,
                created_at,
                updated_at
            FROM task_cards
            WHERE user_id = ? AND repository_url = ?
            ORDER BY created_at ASC, card_id ASC;
            """,
            (user_id, repository_url),
        )
        rows = cursor.fetchall()
        return [self._row_to_task_card(row) for row in rows]

    def _fetch_task_card_by_id(
        self,
        conn: sqlite3.Connection,
        card_id: int,
    ) -> Optional[TaskCardRecord]:
        """
        依 card_id 查詢單一任務卡。

        Args:
            conn (sqlite3.Connection): 既有 SQLite 連線
            card_id (int): 任務卡識別碼

        Returns:
            Optional[TaskCardRecord]: 查詢結果，找不到時為 None

        Examples:
            >>> db._fetch_task_card_by_id(conn, 1)  # doctest: +SKIP

        Raises:
            sqlite3.Error: 查詢資料庫失敗時。
        """
        cursor = conn.execute(
            """
            SELECT
                card_id,
                user_id,
                repository_url,
                task_name,
                task_description,
                task_status,
                created_at,
                updated_at
            FROM task_cards
            WHERE card_id = ?;
            """,
            (card_id,),
        )
        row = cursor.fetchone()
        return self._row_to_task_card(row) if row else None

    def _row_to_task_card(self, row: sqlite3.Row) -> TaskCardRecord:
        """
        將 SQLite 資料列轉換成 TaskCardRecord。

        Args:
            row (sqlite3.Row): 已查詢的資料列

        Returns:
            TaskCardRecord: 轉換後的資料物件

        Examples:
            >>> db._row_to_task_card(row)  # doctest: +SKIP

        Raises:
            None.
        """
        return TaskCardRecord(
            card_id=row["card_id"],
            user_id=row["user_id"],
            repository_url=row["repository_url"],
            task_name=row["task_name"],
            task_description=row["task_description"],
            task_status=row["task_status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _fetch_general_rule(
        self,
        conn: sqlite3.Connection,
        user_id: int,
        repository_url: str,
    ) -> Optional[GeneralRuleRecord]:
        """
        於既有連線內查詢通用規則。

        Args:
            conn (sqlite3.Connection): SQLite 連線
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            Optional[GeneralRuleRecord]: 查詢結果

        Examples:
            >>> db._fetch_general_rule(conn, 1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            sqlite3.Error: 查詢失敗時。
        """
        cursor = conn.execute(
            """
            SELECT user_id, repository_url, rule_content, updated_at
            FROM general_rules
            WHERE user_id = ? AND repository_url = ?;
            """,
            (user_id, repository_url),
        )
        row = cursor.fetchone()
        return self._row_to_general_rule(row) if row else None

    def _row_to_general_rule(self, row: sqlite3.Row) -> GeneralRuleRecord:
        """
        將資料列轉換為 GeneralRuleRecord。

        Args:
            row (sqlite3.Row): SQLite 資料列

        Returns:
            GeneralRuleRecord: 對應的資料實體

        Examples:
            >>> db._row_to_general_rule(row)  # doctest: +SKIP

        Raises:
            None.
        """
        return GeneralRuleRecord(
            user_id=row["user_id"],
            repository_url=row["repository_url"],
            content=row["rule_content"],
            updated_at=row["updated_at"],
        )

    def _fetch_common_tasks(
        self,
        conn: sqlite3.Connection,
        user_id: int,
        repository_url: str,
    ) -> list[CommonTaskRecord]:
        """
        於既有連線內查詢常用任務。

        Args:
            conn (sqlite3.Connection): SQLite 連線
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            list[CommonTaskRecord]: 查詢結果

        Examples:
            >>> db._fetch_common_tasks(conn, 1, "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            sqlite3.Error: 查詢失敗時。
        """
        cursor = conn.execute(
            """
            SELECT task_id, user_id, repository_url, task_content, updated_at
            FROM common_tasks
            WHERE user_id = ? AND repository_url = ?
            ORDER BY task_id ASC;
            """,
            (user_id, repository_url),
        )
        rows = cursor.fetchall()
        return [self._row_to_common_task(row) for row in rows]

    def _row_to_common_task(self, row: sqlite3.Row) -> CommonTaskRecord:
        """
        將資料列轉換為 CommonTaskRecord。

        Args:
            row (sqlite3.Row): SQLite 資料列

        Returns:
            CommonTaskRecord: 對應的資料實體

        Examples:
            >>> db._row_to_common_task(row)  # doctest: +SKIP

        Raises:
            None.
        """
        return CommonTaskRecord(
            task_id=row["task_id"],
            user_id=row["user_id"],
            repository_url=row["repository_url"],
            content=row["task_content"],
            updated_at=row["updated_at"],
        )

    def _normalize_repository_url(self, repository_url: str) -> str:
        """
        正規化儲存庫網址輸入。

        Args:
            repository_url (str): 原始輸入

        Returns:
            str: 去除前後空白的網址

        Examples:
            >>> db._normalize_repository_url(" https://github.com/demo/repo ")  # doctest: +SKIP
            'https://github.com/demo/repo'

        Raises:
            ValueError: 當輸入為空時。
        """
        normalized = repository_url.strip()
        if not normalized:
            raise ValueError("repository_url 不可為空白")
        return normalized

    def _normalize_non_empty_text(self, value: str, field_name: str) -> str:
        """
        驗證字串欄位不可為空白並回傳正規化結果。

        Args:
            value (str): 原始輸入值
            field_name (str): 欄位名稱，用於錯誤訊息

        Returns:
            str: 去除前後空白後的字串

        Examples:
            >>> db._normalize_non_empty_text(" foo ", "task_name")  # doctest: +SKIP
            'foo'

        Raises:
            ValueError: 當 value 去除空白後為空時。
        """
        normalized = value.strip()
        if not normalized:
            raise ValueError(f"{field_name} 不可為空白")
        return normalized

    def _require_positive_user_id(self, user_id: int) -> None:
        """
        驗證 user_id 是否為正整數。

        Args:
            user_id (int): 欲驗證的使用者編號

        Returns:
            None.

        Examples:
            >>> db._require_positive_user_id(1)

        Raises:
            ValueError: 當 user_id 小於等於 0 時。
        """
        if user_id <= 0:
            raise ValueError("user_id 必須為正整數")

    def _prepare_task_contents(self, tasks: Sequence[str]) -> list[str]:
        """
        驗證並正規化常用任務內容。

        Args:
            tasks (Sequence[str]): 任務內容序列

        Returns:
            list[str]: 經過去重與去空白的任務列表

        Examples:
            >>> db._prepare_task_contents([" task "])  # doctest: +SKIP
            ['task']

        Raises:
            ValueError: 當序列為空、包含非字串或空白內容時。
        """
        if tasks is None:
            raise ValueError("tasks 不可為 None")
        normalized: list[str] = []
        seen: set[str] = set()
        for task in tasks:
            if not isinstance(task, str):
                raise ValueError("任務內容必須為字串")
            trimmed = task.strip()
            if not trimmed:
                raise ValueError("任務內容不可為空白")
            if trimmed not in seen:
                seen.add(trimmed)
                normalized.append(trimmed)
        return normalized


class BigQueryDatabase(DatabaseGateway):
    """
    BigQuery 的資料庫實作（佔位，待實作）。

    Args:
        config (dict): BigQuery 初始化參數

    Returns:
        None.

    Examples:
        >>> BigQueryDatabase({"project": "demo"})

    Raises:
        None.
    """

    def __init__(self, config: dict):
        """
        初始化 BigQueryDatabase。

        Args:
            config (dict): BigQuery 設定

        Returns:
            None.

        Examples:
            >>> BigQueryDatabase({"project": "demo"})

        Raises:
            None.
        """
        self._config = config

    def initialize(self) -> None:
        """
        初始化 BigQuery（尚未實作）。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> BigQueryDatabase({}).initialize()

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def create_user(self, account: str, password: str, cursor_api_key: str) -> UserRecord:
        """
        建立 BigQuery 使用者（尚未實作）。

        Args:
            account (str): 帳號
            password (str): 雜湊後密碼
            cursor_api_key (str): Cursor API Key

        Returns:
            UserRecord: 使用者資料

        Examples:
            >>> BigQueryDatabase({}).create_user("a", "b", "c")

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_user_by_account(self, account: str) -> Optional[UserRecord]:
        """
        依帳號取得 BigQuery 使用者（尚未實作）。

        Args:
            account (str): 帳號

        Returns:
            Optional[UserRecord]: 使用者資料

        Examples:
            >>> BigQueryDatabase({}).get_user_by_account("demo")

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_user_by_credentials(self, account: str, password: str) -> Optional[UserRecord]:
        """
        依帳號密碼取得 BigQuery 使用者（尚未實作）。

        Args:
            account (str): 帳號
            password (str): 雜湊後密碼

        Returns:
            Optional[UserRecord]: 使用者資料

        Examples:
            >>> BigQueryDatabase({}).get_user_by_credentials("demo", "hash")

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_user_by_cursor_key(self, cursor_api_key: str) -> Optional[UserRecord]:
        """
        依 Cursor API Key 取得 BigQuery 使用者（尚未實作）。

        Args:
            cursor_api_key (str): Key

        Returns:
            Optional[UserRecord]: 使用者資料

        Examples:
            >>> BigQueryDatabase({}).get_user_by_cursor_key("key")

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def revoke_token(self, access_token: str) -> None:
        """
        註銷 BigQuery Token（尚未實作）。

        Args:
            access_token (str): JWT 字串

        Returns:
            None.

        Examples:
            >>> BigQueryDatabase({}).revoke_token("token")

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def is_token_revoked(self, access_token: str) -> bool:
        """
        檢查 BigQuery Token 是否註銷（尚未實作）。

        Args:
            access_token (str): JWT 字串

        Returns:
            bool: True 表示已註銷

        Examples:
            >>> BigQueryDatabase({}).is_token_revoked("token")

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def ensure_repository_schema(self) -> None:
        """
        建立 repositories 資料表（尚未實作）。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> BigQueryDatabase({}).ensure_repository_schema()  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def ensure_personalization_schema(self) -> None:
        """
        建立通用規則與常用任務資料表（尚未實作）。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> BigQueryDatabase({}).ensure_personalization_schema()  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def ensure_task_card_schema(self) -> None:
        """
        建立 task_cards 資料表（尚未實作）。

        Args:
            None.

        Returns:
            None.

        Examples:
            >>> BigQueryDatabase({}).ensure_task_card_schema()  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def replace_repositories(
        self,
        cursor_api_key: str,
        repositories: Sequence[RepositoryPayload],
    ) -> list[RepositoryRecord]:
        """
        覆寫儲存庫資料（尚未實作）。

        Args:
            cursor_api_key (str): Cursor API Key
            repositories (Sequence[RepositoryPayload]): 儲存庫資料

        Returns:
            list[RepositoryRecord]: 實際寫入資料

        Examples:
            >>> BigQueryDatabase({}).replace_repositories("ck", [])  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def create_task_card(
        self,
        user_id: int,
        repository_url: str,
        task_name: str,
        task_description: str,
        task_status: str,
    ) -> TaskCardRecord:
        """
        建立任務卡（尚未實作）。

        Args:
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址
            task_name (str): 任務名稱
            task_description (str): JSON 字串描述
            task_status (str): 任務狀態

        Returns:
            TaskCardRecord: 任務卡資料

        Examples:
            >>> BigQueryDatabase({}).create_task_card(1, "url", "Task", "[]", "ToDo")  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def list_task_cards(
        self,
        user_id: int,
        repository_url: str,
    ) -> list[TaskCardRecord]:
        """
        取得任務卡列表（尚未實作）。

        Args:
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            list[TaskCardRecord]: 任務卡列表

        Examples:
            >>> BigQueryDatabase({}).list_task_cards(1, "url")  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def update_task_card(
        self,
        card_id: int,
        user_id: int,
        repository_url: str,
        task_name: Optional[str] = None,
        task_description: Optional[str] = None,
        task_status: Optional[str] = None,
    ) -> TaskCardRecord:
        """
        更新任務卡（尚未實作）。

        Args:
            card_id (int): 任務卡識別碼
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址
            task_name (Optional[str]): 新任務名稱
            task_description (Optional[str]): 新任務描述
            task_status (Optional[str]): 新任務狀態

        Returns:
            TaskCardRecord: 更新後的任務卡

        Examples:
            >>> BigQueryDatabase({}).update_task_card(1, 1, "url", task_status="Done")  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def delete_task_card(
        self,
        card_id: int,
        user_id: int,
        repository_url: str,
    ) -> None:
        """
        刪除任務卡（尚未實作）。

        Args:
            card_id (int): 任務卡識別碼
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            None.

        Examples:
            >>> BigQueryDatabase({}).delete_task_card(1, 1, "url")  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_repositories(self, cursor_api_key: str) -> list[RepositoryRecord]:
        """
        取得儲存庫資料（尚未實作）。

        Args:
            cursor_api_key (str): Cursor API Key

        Returns:
            list[RepositoryRecord]: 儲存庫資料

        Examples:
            >>> BigQueryDatabase({}).get_repositories("ck")  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_latest_repository_created_at(self, cursor_api_key: str) -> Optional[str]:
        """
        取得儲存庫最新建立時間（尚未實作）。

        Args:
            cursor_api_key (str): Cursor API Key

        Returns:
            Optional[str]: 最新 created_at

        Examples:
            >>> BigQueryDatabase({}).get_latest_repository_created_at("ck")  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> Optional[GeneralRuleRecord]:
        """
        取得通用規則（尚未實作）。

        Args:
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            Optional[GeneralRuleRecord]: 通用規則

        Examples:
            >>> BigQueryDatabase({}).get_general_rule_by_user(1, "url")  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def upsert_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
        rule_content: str,
    ) -> GeneralRuleRecord:
        """
        新增或更新通用規則（尚未實作）。

        Args:
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址
            rule_content (str): 通用規則內容

        Returns:
            GeneralRuleRecord: 更新後資料

        Examples:
            >>> BigQueryDatabase({}).upsert_general_rule_by_user(1, "url", "rule")  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def list_common_tasks_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> list[CommonTaskRecord]:
        """
        取得常用任務（尚未實作）。

        Args:
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址

        Returns:
            list[CommonTaskRecord]: 常用任務資料

        Examples:
            >>> BigQueryDatabase({}).list_common_tasks_by_user(1, "url")  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")

    def replace_common_tasks_by_user(
        self,
        user_id: int,
        repository_url: str,
        tasks: Sequence[str],
    ) -> list[CommonTaskRecord]:
        """
        覆寫常用任務（尚未實作）。

        Args:
            user_id (int): login_users.user_id
            repository_url (str): 儲存庫網址
            tasks (Sequence[str]): 任務內容

        Returns:
            list[CommonTaskRecord]: 更新後資料

        Examples:
            >>> BigQueryDatabase({}).replace_common_tasks_by_user(1, "url", ["task"])  # doctest: +SKIP

        Raises:
            NotImplementedError: 尚未支援。
        """
        raise NotImplementedError("BigQuery 實作尚未提供")
