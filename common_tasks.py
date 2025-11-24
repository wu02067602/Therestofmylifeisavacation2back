"""
常用任務服務，提供查詢與覆寫功能。
"""

from __future__ import annotations

import logging
from typing import Sequence

from database import DatabaseGateway, UserRecord

logger = logging.getLogger(__name__)


class CommonTaskService:
    """
    負責讀寫常用任務資料的服務類別。

    Args:
        database (DatabaseGateway): 資料庫協調層實作

    Returns:
        None.

    Examples:
        >>> service = CommonTaskService(database)  # doctest: +SKIP

    Raises:
        ValueError: 當初始化參數不合法時。
    """

    def __init__(self, database: DatabaseGateway) -> None:
        """
        初始化 CommonTaskService。

        Args:
            database (DatabaseGateway): 資料庫協調層實作

        Returns:
            None.

        Examples:
            >>> CommonTaskService(database)  # doctest: +SKIP

        Raises:
            ValueError: 當 database 未實作 DatabaseGateway 介面時。
        """
        if not isinstance(database, DatabaseGateway):
            raise ValueError("database 參數必須實作 DatabaseGateway")
        self._database = database

    def list_tasks(self, account: str, repository_url: str) -> list[str]:
        """
        取得指定帳號與儲存庫對應的常用任務清單。

        Args:
            account (str): 使用者帳號
            repository_url (str): 儲存庫網址

        Returns:
            list[str]: 常用任務內容清單，依建立順序排列

        Examples:
            >>> service.list_tasks("demo", "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入為空或找不到使用者時。
            DatabaseError: 資料庫查詢失敗時。
        """
        user = self._get_user_by_account(account)
        records = self._database.list_common_tasks_by_user(user.user_id, repository_url)
        return [record.content for record in records]

    def replace_tasks(self, account: str, repository_url: str, tasks: Sequence[str]) -> list[str]:
        """
        以覆蓋方式更新常用任務，會刪除缺席項目並插入新任務。

        Args:
            account (str): 使用者帳號
            repository_url (str): 儲存庫網址
            tasks (Sequence[str]): 需要保留的常用任務內容

        Returns:
            list[str]: 更新後的常用任務內容清單

        Examples:
            >>> service.replace_tasks("demo", "https://github.com/demo/repo", ["task"])  # doctest: +SKIP

        Raises:
            ValueError: 當輸入為空或找不到使用者時。
            DatabaseError: 資料庫寫入失敗時。
        """
        user = self._get_user_by_account(account)
        records = self._database.replace_common_tasks_by_user(user.user_id, repository_url, tasks)
        logger.info(
            "覆寫常用任務成功: account=%s repository=%s count=%d",
            user.account,
            repository_url,
            len(records),
        )
        return [record.content for record in records]

    def _get_user_by_account(self, account: str) -> UserRecord:
        """
        取得指定帳號的使用者資料。

        Args:
            account (str): 使用者帳號

        Returns:
            UserRecord: 對應的使用者資料列

        Examples:
            >>> service._get_user_by_account("demo")  # doctest: +SKIP

        Raises:
            ValueError: 當帳號為空或使用者不存在時。
            DatabaseError: 資料庫查詢失敗時。
        """
        normalized = account.strip()
        if not normalized:
            raise ValueError("account 不可為空白")
        user = self._database.get_user_by_account(normalized)
        if not user:
            raise ValueError("找不到指定帳號")
        return user
