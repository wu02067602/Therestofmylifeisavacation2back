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
