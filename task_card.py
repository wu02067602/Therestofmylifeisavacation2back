"""
任務卡服務模組，提供取得、建立、更新、刪除等操作。
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from database import DatabaseGateway, TaskCardRecord, UserRecord

logger = logging.getLogger(__name__)

TaskDescriptionPayload = list[dict[str, str]]


class TaskCardService:
    """
    管理任務卡生命週期的服務類別。

    Args:
        database (DatabaseGateway): 資料庫協調層實作

    Returns:
        None.

    Examples:
        >>> service = TaskCardService(database)  # doctest: +SKIP

    Raises:
        ValueError: 當初始化參數不合法時。
    """

    def __init__(self, database: DatabaseGateway) -> None:
        """
        初始化 TaskCardService。

        Args:
            database (DatabaseGateway): 資料庫協調層實作

        Returns:
            None.

        Examples:
            >>> TaskCardService(database)  # doctest: +SKIP

        Raises:
            ValueError: 當 database 未實作 DatabaseGateway 介面時。
        """
        if not isinstance(database, DatabaseGateway):
            raise ValueError("database 參數必須實作 DatabaseGateway")
        self._database = database

    def list_cards(self, account: str, repository_url: str) -> list[dict[str, Any]]:
        """
        取得指定帳號與儲存庫的所有任務卡。

        Args:
            account (str): 使用者帳號
            repository_url (str): 儲存庫網址

        Returns:
            list[dict[str, Any]]: 任務卡資料列表

        Examples:
            >>> service.list_cards("demo", "https://github.com/demo/repo")  # doctest: +SKIP

        Raises:
            ValueError: 當帳號為空或找不到對應使用者時。
            DatabaseError: 當資料庫存取失敗時。
        """
        user = self._get_user_by_account(account)
        records = self._database.list_task_cards(user.user_id, repository_url)
        return [self._record_to_dict(record) for record in records]

    def create_card(
        self,
        account: str,
        repository_url: str,
        task_name: str,
        task_description: TaskDescriptionPayload,
        task_status: str,
    ) -> dict[str, Any]:
        """
        建立新的任務卡。

        Args:
            account (str): 使用者帳號
            repository_url (str): 儲存庫網址
            task_name (str): 任務名稱
            task_description (TaskDescriptionPayload): 任務描述 JSON 陣列
            task_status (str): 任務狀態

        Returns:
            dict[str, Any]: 新建立的任務卡資料

        Examples:
            >>> service.create_card("demo", "https://github.com/demo/repo", "Task", [], "ToDo")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入內容不合法時。
            DatabaseError: 當資料庫寫入失敗時。
        """
        user = self._get_user_by_account(account)
        normalized_name = self._normalize_non_empty_text(task_name, "task_name")
        normalized_status = self._normalize_non_empty_text(task_status, "task_status")
        normalized_description = self._serialize_description(task_description)
        record = self._database.create_task_card(
            user.user_id,
            repository_url,
            normalized_name,
            normalized_description,
            normalized_status,
        )
        logger.info(
            "建立任務卡成功: card_id=%s account=%s repository=%s",
            record.card_id,
            user.account,
            repository_url,
        )
        return self._record_to_dict(record)

    def update_card(
        self,
        account: str,
        repository_url: str,
        card_id: int,
        *,
        task_name: Optional[str] = None,
        task_description: Optional[TaskDescriptionPayload] = None,
        task_status: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        更新指定任務卡的內容。

        Args:
            account (str): 使用者帳號
            repository_url (str): 儲存庫網址
            card_id (int): 任務卡識別碼
            task_name (Optional[str]): 新任務名稱
            task_description (Optional[TaskDescriptionPayload]): 新描述
            task_status (Optional[str]): 新任務狀態

        Returns:
            dict[str, Any]: 更新後的任務卡資料

        Examples:
            >>> service.update_card("demo", "https://github.com/demo/repo", 1, task_status="Done")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入不合法或未指定更新欄位時。
            DatabaseError: 當資料庫更新失敗時。
        """
        if card_id <= 0:
            raise ValueError("card_id 必須為正整數")
        user = self._get_user_by_account(account)
        update_kwargs: dict[str, Optional[str]] = {}
        if task_name is not None:
            update_kwargs["task_name"] = self._normalize_non_empty_text(task_name, "task_name")
        if task_status is not None:
            update_kwargs["task_status"] = self._normalize_non_empty_text(task_status, "task_status")
        if task_description is not None:
            update_kwargs["task_description"] = self._serialize_description(task_description)
        if not update_kwargs:
            raise ValueError("至少需要提供一個可更新欄位")
        record = self._database.update_task_card(
            card_id,
            user.user_id,
            repository_url,
            task_name=update_kwargs.get("task_name"),
            task_description=update_kwargs.get("task_description"),
            task_status=update_kwargs.get("task_status"),
        )
        logger.info(
            "更新任務卡成功: card_id=%s account=%s repository=%s",
            record.card_id,
            user.account,
            repository_url,
        )
        return self._record_to_dict(record)

    def delete_card(self, account: str, repository_url: str, card_id: int) -> None:
        """
        刪除指定任務卡。

        Args:
            account (str): 使用者帳號
            repository_url (str): 儲存庫網址
            card_id (int): 任務卡識別碼

        Returns:
            None.

        Examples:
            >>> service.delete_card("demo", "https://github.com/demo/repo", 1)  # doctest: +SKIP

        Raises:
            ValueError: 當輸入不合法或找不到使用者時。
            DatabaseError: 當資料庫刪除失敗時。
        """
        if card_id <= 0:
            raise ValueError("card_id 必須為正整數")
        user = self._get_user_by_account(account)
        self._database.delete_task_card(card_id, user.user_id, repository_url)
        logger.info(
            "刪除任務卡成功: card_id=%s account=%s repository=%s",
            card_id,
            user.account,
            repository_url,
        )

    def _get_user_by_account(self, account: str) -> UserRecord:
        """
        依帳號取得使用者資料。

        Args:
            account (str): 使用者帳號

        Returns:
            UserRecord: 對應的使用者資料列

        Examples:
            >>> service._get_user_by_account("demo")  # doctest: +SKIP

        Raises:
            ValueError: 當帳號為空或找不到使用者時。
            DatabaseError: 當資料庫查詢失敗時。
        """
        normalized = self._normalize_non_empty_text(account, "account")
        user = self._database.get_user_by_account(normalized)
        if not user:
            raise ValueError("找不到指定帳號")
        return user

    def _serialize_description(self, payload: TaskDescriptionPayload) -> str:
        """
        驗證並序列化任務描述。

        Args:
            payload (TaskDescriptionPayload): 任務描述內容

        Returns:
            str: JSON 格式字串

        Examples:
            >>> service._serialize_description([])  # doctest: +SKIP
            '[]'

        Raises:
            ValueError: 當描述格式不符規範時。
        """
        normalized_entries = self._validate_description_entries(payload)
        return json.dumps(normalized_entries, ensure_ascii=True)

    def _record_to_dict(self, record: TaskCardRecord) -> dict[str, Any]:
        """
        將 TaskCardRecord 轉換為字典並解析描述欄位。

        Args:
            record (TaskCardRecord): 任務卡資料列

        Returns:
            dict[str, Any]: 可序列化的資料字典

        Examples:
            >>> service._record_to_dict(record)  # doctest: +SKIP

        Raises:
            None.
        """
        return {
            "card_id": record.card_id,
            "user_id": record.user_id,
            "repository_url": record.repository_url,
            "task_name": record.task_name,
            "task_description": self._deserialize_description(record.task_description),
            "task_status": record.task_status,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }

    def _deserialize_description(self, raw_value: Any) -> TaskDescriptionPayload:
        """
        將儲存值解析為任務描述陣列。

        Args:
            raw_value (Any): 從資料庫取得的資料

        Returns:
            TaskDescriptionPayload: 任務描述陣列

        Examples:
            >>> service._deserialize_description("[]")  # doctest: +SKIP
            []

        Raises:
            None.
        """
        if isinstance(raw_value, list):
            return self._validate_description_entries(raw_value)
        if isinstance(raw_value, str):
            try:
                parsed = json.loads(raw_value)
            except json.JSONDecodeError:
                logger.warning("無法解析任務描述 JSON，將回傳空陣列")
                return []
            return self._validate_description_entries(parsed)
        logger.warning("未預期的任務描述格式: type=%s", type(raw_value))
        return []

    def _validate_description_entries(self, payload: Any) -> TaskDescriptionPayload:
        """
        驗證任務描述欄位結構。

        Args:
            payload (Any): 原始描述資料

        Returns:
            TaskDescriptionPayload: 驗證後的描述陣列

        Examples:
            >>> service._validate_description_entries([])  # doctest: +SKIP
            []

        Raises:
            ValueError: 當描述項目格式不正確時。
        """
        if payload is None:
            raise ValueError("task_description 不可為 None")
        if not isinstance(payload, list):
            raise ValueError("task_description 必須為陣列")
        normalized: TaskDescriptionPayload = []
        for entry in payload:
            normalized.append(self._normalize_description_entry(entry))
        return normalized

    def _normalize_description_entry(self, entry: Any) -> dict[str, str]:
        """
        驗證並標準化單一描述項目。

        Args:
            entry (Any): 單一描述輸入

        Returns:
            dict[str, str]: 標準化後的描述項目

        Examples:
            >>> service._normalize_description_entry({"type": "custom", "narrative": "text"})  # doctest: +SKIP

        Raises:
            ValueError: 當描述項目格式不正確時。
        """
        if not isinstance(entry, dict):
            raise ValueError("task_description 每個項目都必須是物件")
        entry_type = self._normalize_non_empty_text(entry.get("type", ""), "type")
        validators = {
            "code_responsibility": (["file_name", "class_name", "responsibility"], ["notes"]),
            "modification": (["target", "content"], []),
            "reading": (["target", "content"], []),
            "custom": (["narrative"], []),
        }
        if entry_type not in validators:
            raise ValueError("不支援的描述 type")
        required_fields, optional_fields = validators[entry_type]
        normalized_entry: dict[str, str] = {"type": entry_type}
        for field_name in required_fields:
            value = entry.get(field_name, "")
            normalized_entry[field_name] = self._normalize_non_empty_text(value, field_name)
        for field_name in optional_fields:
            if field_name in entry and entry[field_name] is not None:
                normalized_entry[field_name] = self._normalize_non_empty_text(entry[field_name], field_name)
        return normalized_entry

    def _normalize_non_empty_text(self, value: Any, field_name: str) -> str:
        """
        確保字串欄位為非空白。

        Args:
            value (Any): 欲驗證的值
            field_name (str): 欄位名稱

        Returns:
            str: 去除前後空白後的字串

        Examples:
            >>> service._normalize_non_empty_text(" foo ", "field")  # doctest: +SKIP
            'foo'

        Raises:
            ValueError: 當值不是字串或去除空白後為空時。
        """
        if not isinstance(value, str):
            raise ValueError(f"{field_name} 必須為字串")
        normalized = value.strip()
        if not normalized:
            raise ValueError(f"{field_name} 不可為空白")
        return normalized

