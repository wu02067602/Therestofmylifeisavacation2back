"""
通用規則服務，提供取得與更新功能。
"""

from __future__ import annotations

import logging
from typing import Optional

from database import DatabaseGateway, GeneralRuleRecord, UserRecord

logger = logging.getLogger(__name__)


class GeneralRuleService:
    """
    透過資料庫協調層讀寫通用規則內容的服務類別。

    Args:
        database (DatabaseGateway): 資料庫協調層實作

    Returns:
        None.

    Examples:
        >>> service = GeneralRuleService(database)  # doctest: +SKIP

    Raises:
        ValueError: 當初始化參數不合法時。
    """

    def __init__(self, database: DatabaseGateway) -> None:
        """
        初始化 GeneralRuleService。

        Args:
            database (DatabaseGateway): 資料庫協調層實作

        Returns:
            None.

        Examples:
            >>> GeneralRuleService(database)  # doctest: +SKIP

        Raises:
            ValueError: 當 database 未實作 DatabaseGateway 介面時。
        """
        if not isinstance(database, DatabaseGateway):
            raise ValueError("database 參數必須實作 DatabaseGateway")
        self._database = database

    def get_rule(self, account: str, repository_url: str) -> Optional[str]:
        """
        依帳號與儲存庫網址取得通用規則內容。

        Args:
            account (str): 使用者帳號
            repository_url (str): 儲存庫網址

        Returns:
            Optional[str]: 找到則回傳規則內容，否則 None

        Examples:
            >>> service.get_rule("demo", "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            ValueError: 當帳號或網址為空，或找不到使用者時。
            DatabaseError: 資料庫查詢失敗時。
        """
        record = self.get_rule_record(account, repository_url)
        return record.content if record else None

    def get_rule_record(self, account: str, repository_url: str) -> Optional[GeneralRuleRecord]:
        """
        取得包含最後更新時間在內的完整通用規則資料列。

        Args:
            account (str): 使用者帳號
            repository_url (str): 儲存庫網址

        Returns:
            Optional[GeneralRuleRecord]: 查詢結果

        Examples:
            >>> service.get_rule_record("demo", "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            ValueError: 當帳號或網址為空，或找不到使用者時。
            DatabaseError: 資料庫查詢失敗時。
        """
        user = self._get_user_by_account(account)
        return self._database.get_general_rule_by_user(user.user_id, repository_url)

    def update_rule(self, account: str, repository_url: str, rule_content: str) -> str:
        """
        建立或更新指定帳號與儲存庫的通用規則。

        Args:
            account (str): 使用者帳號
            repository_url (str): 儲存庫網址
            rule_content (str): 通用規則內容

        Returns:
            str: 實際寫入的通用規則內容

        Examples:
            >>> service.update_rule("demo", "https://github.com/demo/repo", "rule")  # doctest: +SKIP

        Raises:
            ValueError: 當欄位為空或找不到使用者時。
            DatabaseError: 資料庫寫入失敗時。
        """
        user = self._get_user_by_account(account)
        record = self._database.upsert_general_rule_by_user(user.user_id, repository_url, rule_content)
        logger.info(
            "更新通用規則成功: account=%s repository=%s",
            user.account,
            repository_url,
        )
        return record.content

    def _get_user_by_account(self, account: str) -> UserRecord:
        """
        取得指定帳號的使用者資料。

        Args:
            account (str): 使用者帳號

        Returns:
            UserRecord: 對應的使用者資料

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
