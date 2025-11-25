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
    """

    repository_owner: str
    repository_name: str
    repository_url: str


@dataclass(frozen=True)
class GeneralRuleRecord:
    """
    代表 general_rules 資料表中的資料列。
    """

    user_id: int
    repository_url: str
    content: str
    updated_at: str


@dataclass(frozen=True)
class CommonTaskRecord:
    """
    代表 common_tasks 資料表中的資料列。
    """

    task_id: int
    user_id: int
    repository_url: str
    content: str
    updated_at: str


@dataclass(frozen=True)
class TaskCardRecord:
    """
    代表 task_cards 資料表中的單一資料列。
    """
    card_id: int
    user_id: int
    repository_url: str
    task_name: str
    task_description: str
    task_status: str
    common_tasks: str
    created_at: str
    updated_at: str


class DatabaseError(RuntimeError):
    """
    所有資料庫相關錯誤的基底類別。
    """


class DatabaseInitializationError(DatabaseError):
    """
    初始化資料庫時發生的錯誤。
    """


class TokenAlreadyRevokedError(DatabaseError):
    """
    嘗試註銷已註銷的 Token 時拋出的錯誤。
    """


class DatabaseGateway(ABC):
    """
    定義多種資料庫實作需遵循的協調介面。
    """

    @abstractmethod
    def initialize(self) -> None:
        """建立必要表格與觸發器。"""

    @abstractmethod
    def create_user(self, account: str, password: str, cursor_api_key: str) -> UserRecord:
        """建立新的登入使用者。"""

    @abstractmethod
    def get_user_by_account(self, account: str) -> Optional[UserRecord]:
        """依帳號尋找使用者。"""

    @abstractmethod
    def get_user_by_credentials(self, account: str, password: str) -> Optional[UserRecord]:
        """依帳號與密碼尋找使用者。"""

    @abstractmethod
    def get_user_by_cursor_key(self, cursor_api_key: str) -> Optional[UserRecord]:
        """依 Cursor API Key 取得使用者。"""

    @abstractmethod
    def revoke_token(self, access_token: str) -> None:
        """註銷 JWT Token。"""

    @abstractmethod
    def is_token_revoked(self, access_token: str) -> bool:
        """檢查 Token 是否已註銷。"""

    @abstractmethod
    def ensure_repository_schema(self) -> None:
        """建立 repositories 資料表與必要索引。"""

    @abstractmethod
    def ensure_personalization_schema(self) -> None:
        """建立通用規則與常用任務相關資料表。"""

    @abstractmethod
    def ensure_task_card_schema(self) -> None:
        """建立 task_cards 資料表。"""

    @abstractmethod
    def replace_repositories(
        self,
        cursor_api_key: str,
        repositories: Sequence[RepositoryPayload],
    ) -> list[RepositoryRecord]:
        """以覆蓋方式寫入指定 Cursor API Key 的儲存庫。"""

    @abstractmethod
    def get_repositories(self, cursor_api_key: str) -> list[RepositoryRecord]:
        """取得指定 Cursor API Key 的儲存庫清單。"""

    @abstractmethod
    def get_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> Optional[GeneralRuleRecord]:
        """取得指定使用者與儲存庫對應的通用規則。"""

    @abstractmethod
    def upsert_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
        rule_content: str,
    ) -> GeneralRuleRecord:
        """建立或更新指定使用者與儲存庫的通用規則。"""

    @abstractmethod
    def list_common_tasks_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> list[CommonTaskRecord]:
        """取得指定使用者與儲存庫的常用任務清單。"""

    @abstractmethod
    def replace_common_tasks_by_user(
        self,
        user_id: int,
        repository_url: str,
        tasks: Sequence[str],
    ) -> list[CommonTaskRecord]:
        """以覆蓋方式更新指定使用者與儲存庫的常用任務。"""

    @abstractmethod
    def create_task_card(
        self,
        user_id: int,
        repository_url: str,
        task_name: str,
        task_description: str,
        task_status: str,
        common_tasks: str,
    ) -> TaskCardRecord:
        """建立任務卡。"""

    @abstractmethod
    def get_task_card_by_id(self, card_id: int, user_id: int) -> Optional[TaskCardRecord]:
        """取得任務卡。"""

    @abstractmethod
    def list_task_cards_by_user(self, user_id: int, repository_url: Optional[str]) -> list[TaskCardRecord]:
        """列出任務卡。"""

    @abstractmethod
    def update_task_card(
        self,
        card_id: int,
        user_id: int,
        *,
        task_name: Optional[str] = None,
        task_description: Optional[str] = None,
        task_status: Optional[str] = None,
        repository_url: Optional[str] = None,
        common_tasks: Optional[str] = None,
    ) -> TaskCardRecord:
        """更新任務卡。"""

    @abstractmethod
    def delete_task_card(self, card_id: int, user_id: int) -> None:
        """刪除任務卡。"""

    @abstractmethod
    def get_latest_repository_created_at(self, cursor_api_key: str) -> Optional[str]:
        """取得儲存庫資料的最新建立時間。"""


def create_database(backend: str, **kwargs) -> DatabaseGateway:
    """
    依資料庫類型建立對應的實作。
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
    """

    def __init__(self, db_path: str | Path):
        if not str(db_path).strip():
            raise ValueError("SQLite db_path 不可為空字串")
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

    def initialize(self) -> None:
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
        try:
            with self._connect() as conn:
                self._create_repository_table(conn)
                conn.commit()
        except sqlite3.Error as exc:
            logger.exception("建立 repositories 資料表失敗: %s", exc)
            raise DatabaseInitializationError("建立 repositories 資料表失敗") from exc

    def ensure_personalization_schema(self) -> None:
        try:
            with self._connect() as conn:
                self._create_personalization_tables(conn)
                conn.commit()
        except sqlite3.Error as exc:
            logger.exception("建立 personalization 資料表失敗: %s", exc)
            raise DatabaseInitializationError("建立 personalization 資料表失敗") from exc

    def ensure_task_card_schema(self) -> None:
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
        if not cursor_api_key:
            raise ValueError("cursor_api_key 不可為空")
        try:
            with self._connect() as conn:
                return self._fetch_repositories(conn, cursor_api_key)
        except sqlite3.Error as exc:
            logger.exception("查詢儲存庫資料失敗: key=%s exc=%s", cursor_api_key, exc)
            raise DatabaseError("查詢儲存庫資料失敗") from exc

    def get_latest_repository_created_at(self, cursor_api_key: str) -> Optional[str]:
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

    def get_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> Optional[GeneralRuleRecord]:
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

    def create_task_card(
        self,
        user_id: int,
        repository_url: str,
        task_name: str,
        task_description: str,
        task_status: str,
        common_tasks: str,
    ) -> TaskCardRecord:
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO task_cards (
                        user_id, repository_url, task_name,
                        task_description, task_status, common_tasks
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (user_id, repository_url, task_name, task_description, task_status, common_tasks),
                )
                card_id = cursor.lastrowid
                conn.commit()
                record = self._fetch_task_card_by_id(conn, card_id, user_id) # type: ignore
                if not record:
                     raise DatabaseError("無法取得剛建立的任務卡")
                return record
        except sqlite3.Error as exc:
            logger.exception("建立任務卡失敗: %s", exc)
            raise DatabaseError("建立 SQLite 任務卡失敗") from exc

    def get_task_card_by_id(self, card_id: int, user_id: int) -> Optional[TaskCardRecord]:
         try:
            with self._connect() as conn:
                return self._fetch_task_card_by_id(conn, card_id, user_id)
         except sqlite3.Error as exc:
            logger.exception("取得任務卡失敗: %s", exc)
            raise DatabaseError("取得 SQLite 任務卡失敗") from exc

    def list_task_cards_by_user(self, user_id: int, repository_url: Optional[str]) -> list[TaskCardRecord]:
        try:
            with self._connect() as conn:
                query = """
                    SELECT card_id, user_id, repository_url, task_name,
                           task_description, task_status, common_tasks, created_at, updated_at
                    FROM task_cards
                    WHERE user_id = ?
                """
                params: list[Any] = [user_id]
                if repository_url is not None:
                    query += " AND repository_url = ?"
                    params.append(repository_url)
                query += " ORDER BY created_at DESC;"
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
                return [self._row_to_task_card(row) for row in rows]
        except sqlite3.Error as exc:
            logger.exception("列出任務卡失敗: %s", exc)
            raise DatabaseError("列出 SQLite 任務卡失敗") from exc

    def update_task_card(
        self,
        card_id: int,
        user_id: int,
        *,
        task_name: Optional[str] = None,
        task_description: Optional[str] = None,
        task_status: Optional[str] = None,
        repository_url: Optional[str] = None,
        common_tasks: Optional[str] = None,
    ) -> TaskCardRecord:
        updates = []
        params: list[Any] = []
        if task_name is not None:
            updates.append("task_name = ?")
            params.append(task_name)
        if task_description is not None:
            updates.append("task_description = ?")
            params.append(task_description)
        if task_status is not None:
            updates.append("task_status = ?")
            params.append(task_status)
        if repository_url is not None:
            updates.append("repository_url = ?")
            params.append(repository_url)
        if common_tasks is not None:
            updates.append("common_tasks = ?")
            params.append(common_tasks)

        if not updates:
             raise ValueError("無更新欄位")

        params.append(card_id)
        params.append(user_id)

        try:
            with self._connect() as conn:
                conn.execute(
                    f"""
                    UPDATE task_cards
                    SET {', '.join(updates)}
                    WHERE card_id = ? AND user_id = ?;
                    """,
                    params,
                )
                conn.commit()
                record = self._fetch_task_card_by_id(conn, card_id, user_id)
                if not record:
                     raise DatabaseError("更新後無法取得任務卡 (可能已刪除)")
                return record
        except sqlite3.Error as exc:
            logger.exception("更新任務卡失敗: %s", exc)
            raise DatabaseError("更新 SQLite 任務卡失敗") from exc

    def delete_task_card(self, card_id: int, user_id: int) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM task_cards WHERE card_id = ? AND user_id = ?;",
                    (card_id, user_id),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.exception("刪除任務卡失敗: %s", exc)
            raise DatabaseError("刪除 SQLite 任務卡失敗") from exc

    def create_user(self, account: str, password: str, cursor_api_key: str) -> UserRecord:
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
                return self._fetch_user_by_account(conn, account) # type: ignore
        except sqlite3.Error as exc:
            logger.exception("建立使用者時發生錯誤: account=%s exc=%s", account, exc)
            raise DatabaseError("建立 SQLite 使用者資料失敗") from exc

    def get_user_by_account(self, account: str) -> Optional[UserRecord]:
        try:
            with self._connect() as conn:
                return self._fetch_user_by_account(conn, account)
        except sqlite3.Error as exc:
            logger.exception("查詢使用者時發生錯誤: account=%s exc=%s", account, exc)
            raise DatabaseError("查詢 SQLite 使用者資料失敗") from exc

    def get_user_by_credentials(self, account: str, password: str) -> Optional[UserRecord]:
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
        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as exc:
            logger.exception("無法建立 SQLite 連線: %s", exc)
            raise DatabaseError("無法建立 SQLite 連線") from exc

    def _create_repository_table(self, conn: sqlite3.Connection) -> None:
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

    def _create_personalization_tables(self, conn: sqlite3.Connection) -> None:
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS task_cards (
                card_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                repository_url TEXT NOT NULL,
                task_name TEXT NOT NULL,
                task_description TEXT NOT NULL,
                task_status TEXT NOT NULL,
                common_tasks TEXT NOT NULL DEFAULT '[]',
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

    def _fetch_repositories(
        self,
        conn: sqlite3.Connection,
        cursor_api_key: str,
    ) -> list[RepositoryRecord]:
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
        return RepositoryRecord(
            repository_id=row["repository_id"],
            cursor_api_key=row["cursor_api_key"],
            repository_owner=row["repository_owner"],
            repository_name=row["repository_name"],
            repository_url=row["repository_url"],
            created_at=row["created_at"],
        )

    def _fetch_general_rule(
        self,
        conn: sqlite3.Connection,
        user_id: int,
        repository_url: str,
    ) -> Optional[GeneralRuleRecord]:
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
        return CommonTaskRecord(
            task_id=row["task_id"],
            user_id=row["user_id"],
            repository_url=row["repository_url"],
            content=row["task_content"],
            updated_at=row["updated_at"],
        )

    def _fetch_task_card_by_id(self, conn: sqlite3.Connection, card_id: int, user_id: int) -> Optional[TaskCardRecord]:
        cursor = conn.execute(
            """
            SELECT card_id, user_id, repository_url, task_name,
                   task_description, task_status, common_tasks, created_at, updated_at
            FROM task_cards
            WHERE card_id = ? AND user_id = ?;
            """,
            (card_id, user_id),
        )
        row = cursor.fetchone()
        return self._row_to_task_card(row) if row else None

    def _row_to_task_card(self, row: sqlite3.Row) -> TaskCardRecord:
        return TaskCardRecord(
            card_id=row["card_id"],
            user_id=row["user_id"],
            repository_url=row["repository_url"],
            task_name=row["task_name"],
            task_description=row["task_description"],
            task_status=row["task_status"],
            common_tasks=row["common_tasks"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _normalize_repository_url(self, repository_url: str) -> str:
        normalized = repository_url.strip()
        if not normalized:
            raise ValueError("repository_url 不可為空白")
        return normalized

    def _require_positive_user_id(self, user_id: int) -> None:
        if user_id <= 0:
            raise ValueError("user_id 必須為正整數")

    def _prepare_task_contents(self, tasks: Sequence[str]) -> list[str]:
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
    """

    def __init__(self, config: dict):
        self._config = config

    def initialize(self) -> None:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def create_user(self, account: str, password: str, cursor_api_key: str) -> UserRecord:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_user_by_account(self, account: str) -> Optional[UserRecord]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_user_by_credentials(self, account: str, password: str) -> Optional[UserRecord]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_user_by_cursor_key(self, cursor_api_key: str) -> Optional[UserRecord]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def revoke_token(self, access_token: str) -> None:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def is_token_revoked(self, access_token: str) -> bool:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def ensure_repository_schema(self) -> None:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def ensure_personalization_schema(self) -> None:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def ensure_task_card_schema(self) -> None:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def replace_repositories(
        self,
        cursor_api_key: str,
        repositories: Sequence[RepositoryPayload],
    ) -> list[RepositoryRecord]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_repositories(self, cursor_api_key: str) -> list[RepositoryRecord]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_latest_repository_created_at(self, cursor_api_key: str) -> Optional[str]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> Optional[GeneralRuleRecord]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def upsert_general_rule_by_user(
        self,
        user_id: int,
        repository_url: str,
        rule_content: str,
    ) -> GeneralRuleRecord:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def list_common_tasks_by_user(
        self,
        user_id: int,
        repository_url: str,
    ) -> list[CommonTaskRecord]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def replace_common_tasks_by_user(
        self,
        user_id: int,
        repository_url: str,
        tasks: Sequence[str],
    ) -> list[CommonTaskRecord]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def create_task_card(
        self,
        user_id: int,
        repository_url: str,
        task_name: str,
        task_description: str,
        task_status: str,
        common_tasks: str,
    ) -> TaskCardRecord:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def get_task_card_by_id(self, card_id: int, user_id: int) -> Optional[TaskCardRecord]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def list_task_cards_by_user(self, user_id: int, repository_url: Optional[str]) -> list[TaskCardRecord]:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def update_task_card(
        self,
        card_id: int,
        user_id: int,
        *,
        task_name: Optional[str] = None,
        task_description: Optional[str] = None,
        task_status: Optional[str] = None,
        repository_url: Optional[str] = None,
        common_tasks: Optional[str] = None,
    ) -> TaskCardRecord:
        raise NotImplementedError("BigQuery 實作尚未提供")

    def delete_task_card(self, card_id: int, user_id: int) -> None:
        raise NotImplementedError("BigQuery 實作尚未提供")
