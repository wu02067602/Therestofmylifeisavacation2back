"""
任務卡服務模組，提供 CRUD 與輸入驗證。
"""

from __future__ import annotations

import json
import logging
from typing import Any, Mapping, MutableSequence, Optional, Sequence

from database import DatabaseGateway, TaskCardRecord, UserRecord

logger = logging.getLogger(__name__)

ALLOWED_TASK_STATUSES = {"ToDo", "InProgress", "Done"}
ALLOWED_DESCRIPTION_TYPES = {
    "code_responsibility",
    "modification",
    "reading",
    "custom",
}


class TaskCardNotFoundError(ValueError):
    """
    任務卡不存在時拋出的錯誤。

    Args:
        message (str): 錯誤訊息

    Returns:
        None.

    Examples:
        >>> raise TaskCardNotFoundError("找不到任務卡")
        Traceback (most recent call last):
        ...
        TaskCardNotFoundError: 找不到任務卡

    Raises:
        None.
    """


class InvalidTaskDescriptionError(ValueError):
    """
    任務描述格式錯誤時拋出的錯誤。

    Args:
        message (str): 錯誤訊息

    Returns:
        None.

    Examples:
        >>> raise InvalidTaskDescriptionError("描述錯誤")
        Traceback (most recent call last):
        ...
        InvalidTaskDescriptionError: 描述錯誤

    Raises:
        None.
    """


class TaskCardService:
    """
    封裝任務卡 CRUD 邏輯的服務類別。

    Args:
        database (DatabaseGateway): 資料庫協調層實作

    Returns:
        None.

    Examples:
        >>> service = TaskCardService(database)  # doctest: +SKIP

    Raises:
        ValueError: 當 database 不是 DatabaseGateway 實作時。
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
            ValueError: 當 database 不是 DatabaseGateway 實作時。
        """
        if not isinstance(database, DatabaseGateway):
            raise ValueError("database 參數必須實作 DatabaseGateway")
        self._database = database

    def list_cards(self, account: str, repository_url: Optional[str] = None) -> list[TaskCardRecord]:
        """
        取得指定帳號的任務卡列表。

        Args:
            account (str): 使用者帳號
            repository_url (Optional[str]): 儲存庫網址，None 代表全部

        Returns:
            list[TaskCardRecord]: 任務卡資料清單

        Examples:
            >>> service.list_cards("demo")  # doctest: +SKIP

        Raises:
            ValueError: 當帳號為空或不存在時。
            DatabaseError: 資料庫查詢失敗時。
        """
        user = self._get_user_by_account(account)
        normalized_repo = self._normalize_optional_repository_url(repository_url)
        return self._database.list_task_cards_by_user(user.user_id, normalized_repo)

    def get_card(self, account: str, card_id: int) -> TaskCardRecord:
        """
        取得指定帳號擁有的單一任務卡。

        Args:
            account (str): 使用者帳號
            card_id (int): 任務卡主鍵

        Returns:
            TaskCardRecord: 對應的任務卡

        Examples:
            >>> service.get_card("demo", 1)  # doctest: +SKIP

        Raises:
            ValueError: 當輸入為空或帳號不存在時。
            TaskCardNotFoundError: 當任務卡不存在時。
            DatabaseError: 資料庫查詢失敗時。
        """
        user = self._get_user_by_account(account)
        record = self._database.get_task_card_by_id(card_id, user.user_id)
        if record is None:
            raise TaskCardNotFoundError("找不到指定任務卡")
        return record

    def create_card(
        self,
        account: str,
        repository_url: str,
        task_name: str,
        task_description: Sequence[Mapping[str, Any]],
        task_status: str,
    ) -> TaskCardRecord:
        """
        建立新的任務卡。

        Args:
            account (str): 使用者帳號
            repository_url (str): 儲存庫網址
            task_name (str): 任務名稱
            task_description (Sequence[Mapping[str, Any]]): 任務描述列表
            task_status (str): 任務狀態

        Returns:
            TaskCardRecord: 新建立的任務卡

        Examples:
            >>> service.create_card("demo", "https://github.com/demo/repo", "登入功能", [], "ToDo")  # doctest: +SKIP

        Raises:
            ValueError: 當輸入為空或帳號不存在時。
            InvalidTaskDescriptionError: 任務描述格式錯誤時。
            DatabaseError: 資料庫寫入失敗時。
        """
        user = self._get_user_by_account(account)
        normalized_repo = self._normalize_repository_url(repository_url)
        normalized_name = self._normalize_task_name(task_name)
        normalized_status = self._normalize_task_status(task_status)
        serialized_description = self._serialize_description(task_description)
        record = self._database.create_task_card(
            user.user_id,
            normalized_repo,
            normalized_name,
            serialized_description,
            normalized_status,
        )
        logger.info(
            "建立任務卡成功: account=%s card_id=%s repository=%s",
            user.account,
            record.card_id,
            record.repository_url,
        )
        return record

    def update_card(
        self,
        account: str,
        card_id: int,
        *,
        repository_url: Optional[str] = None,
        task_name: Optional[str] = None,
        task_description: Optional[Sequence[Mapping[str, Any]]] = None,
        task_status: Optional[str] = None,
    ) -> TaskCardRecord:
        """
        更新既有任務卡。

        Args:
            account (str): 使用者帳號
            card_id (int): 任務卡主鍵
            repository_url (Optional[str]): 新儲存庫網址
            task_name (Optional[str]): 新任務名稱
            task_description (Optional[Sequence[Mapping[str, Any]]]): 新任務描述列表
            task_status (Optional[str]): 新任務狀態

        Returns:
            TaskCardRecord: 更新後的任務卡

        Examples:
            >>> service.update_card("demo", 1, task_status="Done")  # doctest: +SKIP

        Raises:
            ValueError: 當沒有任何更新欄位或帳號不存在時。
            InvalidTaskDescriptionError: 任務描述格式錯誤時。
            TaskCardNotFoundError: 任務卡不存在時。
            DatabaseError: 資料庫寫入失敗時。
        """
        user = self._get_user_by_account(account)
        existing = self._database.get_task_card_by_id(card_id, user.user_id)
        if existing is None:
            raise TaskCardNotFoundError("找不到指定任務卡")
        updates: dict[str, Optional[str]] = {}
        if repository_url is not None:
            updates["repository_url"] = self._normalize_repository_url(repository_url)
        if task_name is not None:
            updates["task_name"] = self._normalize_task_name(task_name)
        if task_description is not None:
            updates["task_description"] = self._serialize_description(task_description)
        if task_status is not None:
            updates["task_status"] = self._normalize_task_status(task_status)
        if not updates:
            raise ValueError("至少需要一個可更新的欄位")

        record = self._database.update_task_card(
            card_id,
            user.user_id,
            task_name=updates.get("task_name"),
            task_description=updates.get("task_description"),
            task_status=updates.get("task_status"),
            repository_url=updates.get("repository_url"),
        )
        logger.info(
            "更新任務卡成功: account=%s card_id=%s",
            user.account,
            card_id,
        )
        return record

    def delete_card(self, account: str, card_id: int) -> TaskCardRecord:
        """
        刪除指定任務卡。

        Args:
            account (str): 使用者帳號
            card_id (int): 任務卡主鍵

        Returns:
            TaskCardRecord: 已刪除的任務卡

        Examples:
            >>> service.delete_card("demo", 1)  # doctest: +SKIP

        Raises:
            ValueError: 當帳號不存在時。
            TaskCardNotFoundError: 任務卡不存在時。
            DatabaseError: 資料庫寫入失敗時。
        """
        user = self._get_user_by_account(account)
        existing = self._database.get_task_card_by_id(card_id, user.user_id)
        if existing is None:
            raise TaskCardNotFoundError("找不到指定任務卡")
        self._database.delete_task_card(card_id, user.user_id)
        logger.info("刪除任務卡成功: account=%s card_id=%s", user.account, card_id)
        return existing

    def _get_user_by_account(self, account: str) -> UserRecord:
        """
        取得指定帳號的使用者。

        Args:
            account (str): 使用者帳號

        Returns:
            UserRecord: 使用者資料列

        Examples:
            >>> service._get_user_by_account("demo")  # doctest: +SKIP

        Raises:
            ValueError: 當帳號為空或不存在時。
            DatabaseError: 資料庫查詢失敗時。
        """
        normalized = account.strip()
        if not normalized:
            raise ValueError("account 不可為空白")
        user = self._database.get_user_by_account(normalized)
        if not user:
            raise ValueError("找不到指定帳號")
        return user

    def _normalize_repository_url(self, repository_url: str) -> str:
        """
        驗證並去除儲存庫網址的前後空白。

        Args:
            repository_url (str): 原始儲存庫網址

        Returns:
            str: 正規化後的網址

        Examples:
            >>> service._normalize_repository_url(" https://github.com/demo ")  # doctest: +SKIP
            'https://github.com/demo'

        Raises:
            ValueError: 當輸入為空白時。
        """
        normalized = repository_url.strip()
        if not normalized:
            raise ValueError("repositoryUrl 不可為空白")
        return normalized

    def _normalize_optional_repository_url(self, repository_url: Optional[str]) -> Optional[str]:
        """
        正規化可選的儲存庫網址。

        Args:
            repository_url (Optional[str]): 儲存庫網址或 None

        Returns:
            Optional[str]: 正規化後的網址或 None

        Examples:
            >>> service._normalize_optional_repository_url(None) is None
            True

        Raises:
            ValueError: 當輸入為空白字串時。
        """
        if repository_url is None:
            return None
        return self._normalize_repository_url(repository_url)

    def _normalize_task_name(self, task_name: str) -> str:
        """
        正規化任務名稱。

        Args:
            task_name (str): 任務名稱

        Returns:
            str: 去除空白後的任務名稱

        Examples:
            >>> service._normalize_task_name(" 任務 ")  # doctest: +SKIP
            '任務'

        Raises:
            ValueError: 當輸入為空時。
        """
        normalized = task_name.strip()
        if not normalized:
            raise ValueError("task_name 不可為空白")
        return normalized

    def _normalize_task_status(self, task_status: str) -> str:
        """
        驗證並回傳任務狀態。

        Args:
            task_status (str): 任務狀態

        Returns:
            str: 允許的任務狀態

        Examples:
            >>> service._normalize_task_status("ToDo")  # doctest: +SKIP
            'ToDo'

        Raises:
            ValueError: 當輸入無效或非允許狀態時。
        """
        normalized = task_status.strip()
        if not normalized:
            raise ValueError("task_status 不可為空白")
        if normalized not in ALLOWED_TASK_STATUSES:
            raise ValueError(f"task_status 僅允許 {sorted(ALLOWED_TASK_STATUSES)}")
        return normalized

    def _serialize_description(self, task_description: Sequence[Mapping[str, Any]]) -> str:
        """
        驗證並將任務描述序列化為 JSON。

        Args:
            task_description (Sequence[Mapping[str, Any]]): 任務描述列表

        Returns:
            str: JSON 字串

        Examples:
            >>> service._serialize_description([])  # doctest: +SKIP
            '[]'

        Raises:
            InvalidTaskDescriptionError: 當輸入格式錯誤時。
        """
        if task_description is None:
            raise InvalidTaskDescriptionError("task_description 不可為 None")
        if isinstance(task_description, (str, bytes)):
            raise InvalidTaskDescriptionError("task_description 必須為物件列表")
        normalized_items: MutableSequence[dict[str, Any]] = []
        for index, item in enumerate(task_description):
            if not isinstance(item, Mapping):
                raise InvalidTaskDescriptionError(f"第 {index} 筆描述必須為物件")
            normalized_items.append(self._validate_description_item(item, index))
        return json.dumps(normalized_items, ensure_ascii=False, separators=(",", ":"))

    def _validate_description_item(self, item: Mapping[str, Any], index: int) -> dict[str, Any]:
        """
        驗證並回傳單一任務描述物件。

        Args:
            item (Mapping[str, Any]): 任務描述物件
            index (int): 序號，用於錯誤訊息

        Returns:
            dict[str, Any]: 正規化後的描述物件

        Examples:
            >>> service._validate_description_item({"type": "custom", "narrative": "demo"}, 0)  # doctest: +SKIP
            {'type': 'custom', 'narrative': 'demo'}

        Raises:
            InvalidTaskDescriptionError: 當描述不符合規格時。
        """
        description_type = str(item.get("type", "")).strip()
        if description_type not in ALLOWED_DESCRIPTION_TYPES:
            raise InvalidTaskDescriptionError(f"第 {index} 筆描述的 type 無效")
        normalized: dict[str, Any] = {"type": description_type}
        if description_type == "code_responsibility":
            required_fields = ("file_name", "class_name", "responsibility")
            for field in required_fields:
                normalized[field] = self._require_non_empty_field(item, field, index)
            notes = item.get("notes")
            if notes is not None:
                normalized["notes"] = str(notes).strip()
        elif description_type in ("modification", "reading"):
            normalized["target"] = self._require_non_empty_field(item, "target", index)
            normalized["content"] = self._require_non_empty_field(item, "content", index)
            notes = item.get("notes")
            if notes is not None:
                normalized["notes"] = str(notes).strip()
        elif description_type == "custom":
            normalized["narrative"] = self._require_non_empty_field(item, "narrative", index)
        return normalized

    def _require_non_empty_field(self, item: Mapping[str, Any], field: str, index: int) -> str:
        """
        驗證描述物件中的指定欄位不可為空。

        Args:
            item (Mapping[str, Any]): 任務描述物件
            field (str): 欄位名稱
            index (int): 描述序號

        Returns:
            str: 去除空白後的欄位值

        Examples:
            >>> service._require_non_empty_field({"target": "foo"}, "target", 0)  # doctest: +SKIP
            'foo'

        Raises:
            InvalidTaskDescriptionError: 當欄位缺漏或為空時。
        """
        value = str(item.get(field, "")).strip()
        if not value:
            raise InvalidTaskDescriptionError(f"第 {index} 筆描述缺少 {field}")
        return value
