"""
儲存庫資料同步模組，負責呼叫 Cursor API 並處理快取邏輯。
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Sequence

import httpx

from database import DatabaseGateway, RepositoryPayload, RepositoryRecord

logger = logging.getLogger(__name__)


class RepositoryFetchError(RuntimeError):
    """
    呼叫 Cursor API 失敗時拋出的錯誤。

    Args:
        message (str): 錯誤訊息

    Returns:
        None.

    Examples:
        >>> raise RepositoryFetchError("呼叫失敗")
        Traceback (most recent call last):
        ...
        RepositoryFetchError: 呼叫失敗

    Raises:
        None.
    """


class CursorRepositoryService:
    """
    提供透過 Cursor API 取得 GitHub 儲存庫並以資料庫快取的服務。

    Args:
        database (DatabaseGateway): 資料庫協調層實作
        base_url (str): Cursor API 的根網址
        http_timeout (float): HTTP 請求逾時秒數
        cache_ttl_minutes (int): 快取有效分鐘數

    Returns:
        None.

    Examples:
        >>> service = CursorRepositoryService(db)  # doctest: +SKIP

    Raises:
        ValueError: 初始化參數不合法時。
    """

    def __init__(
        self,
        database: DatabaseGateway,
        base_url: str = "https://api.cursor.com",
        http_timeout: float = 30.0,
        cache_ttl_minutes: int = 30,
    ) -> None:
        """
        初始化 CursorRepositoryService。

        Args:
            database (DatabaseGateway): 資料庫協調層實作
            base_url (str): Cursor API 根網址
            http_timeout (float): HTTP 請求逾時秒數
            cache_ttl_minutes (int): 快取有效分鐘數

        Returns:
            None.

        Examples:
            >>> CursorRepositoryService(db)  # doctest: +SKIP

        Raises:
            ValueError: 當 base_url 為空或 cache_ttl_minutes 非正整數時。
        """
        if not isinstance(database, DatabaseGateway):
            raise ValueError("database 參數必須實作 DatabaseGateway")
        if not base_url:
            raise ValueError("base_url 不可為空")
        if cache_ttl_minutes <= 0:
            raise ValueError("cache_ttl_minutes 必須為正整數")
        if http_timeout <= 0:
            raise ValueError("http_timeout 必須為正數")

        self._database = database
        self._base_url = base_url.rstrip("/")
        self._http_timeout = http_timeout
        self._cache_ttl = timedelta(minutes=cache_ttl_minutes)

    def get_repositories(self, cursor_api_key: str) -> list[RepositoryRecord]:
        """
        取得指定 Cursor API Key 可存取的儲存庫清單。

        Args:
            cursor_api_key (str): Cursor API Key

        Returns:
            list[RepositoryRecord]: 儲存庫資料列

        Examples:
            >>> service.get_repositories("ck_live_xxx")  # doctest: +SKIP

        Raises:
            ValueError: cursor_api_key 為空時。
            RepositoryFetchError: 呼叫 Cursor API 失敗時。
            DatabaseError: 資料庫操作失敗時。
        """
        if not cursor_api_key:
            raise ValueError("cursor_api_key 不可為空")

        last_synced_at = self._database.get_latest_repository_created_at(cursor_api_key)
        if self._is_cache_valid(last_synced_at):
            logger.info("命中儲存庫快取: cursor_api_key=%s", cursor_api_key[:4] + "***")
            return self._database.get_repositories(cursor_api_key)

        payloads = self._fetch_remote_repositories(cursor_api_key)
        records = self._database.replace_repositories(cursor_api_key, payloads)
        logger.info("遠端同步完成: cursor_api_key=%s repository_count=%d", cursor_api_key[:4] + "***", len(records))
        return records

    def _is_cache_valid(self, last_synced_at: Optional[str]) -> bool:
        """
        判斷資料庫中的儲存庫資料是否仍在快取期間內。

        Args:
            last_synced_at (Optional[str]): 最新的 created_at 字串

        Returns:
            bool: True 代表仍在有效期間，可直接使用資料庫

        Examples:
            >>> service._is_cache_valid("2024-01-01 00:00:00")  # doctest: +SKIP
            True

        Raises:
            None.
        """
        if not last_synced_at:
            return False
        try:
            synced_time = self._parse_timestamp(last_synced_at)
        except ValueError:
            logger.warning("created_at 無法解析，將重新同步: raw=%s", last_synced_at)
            return False
        now = datetime.now(timezone.utc)
        return now - synced_time < self._cache_ttl

    def _fetch_remote_repositories(self, cursor_api_key: str) -> list[RepositoryPayload]:
        """
        透過 Cursor API 取得儲存庫資料。

        Args:
            cursor_api_key (str): Cursor API Key

        Returns:
            list[RepositoryPayload]: 遠端回傳的儲存庫清單

        Examples:
            >>> service._fetch_remote_repositories("ck_live_xxx")  # doctest: +SKIP

        Raises:
            RepositoryFetchError: HTTP 回應非 2xx 或資料格式錯誤時。
        """
        url = f"{self._base_url}/v0/repositories"
        try:
            response = httpx.get(
                url,
                auth=(cursor_api_key, ""),
                timeout=self._http_timeout,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.error("Cursor API 回應非 2xx: status=%s body=%s", exc.response.status_code, exc.response.text)
            raise RepositoryFetchError(f"Cursor API 回應錯誤: {exc.response.status_code}") from exc
        except httpx.RequestError as exc:
            logger.error("Cursor API 連線失敗: %s", exc)
            raise RepositoryFetchError("Cursor API 連線失敗") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            logger.error("Cursor API 回傳非 JSON: body=%s", response.text)
            raise RepositoryFetchError("Cursor API 回傳非 JSON 格式") from exc

        repositories = self._parse_repository_payload(payload)
        return repositories

    def _parse_repository_payload(self, payload: dict[str, Any]) -> list[RepositoryPayload]:
        """
        驗證 Cursor API 回傳內容並轉換為 RepositoryPayload。

        Args:
            payload (dict[str, Any]): Cursor API 回應 JSON

        Returns:
            list[RepositoryPayload]: 轉換後的資料清單

        Examples:
            >>> service._parse_repository_payload({'repositories': []})  # doctest: +SKIP
            []

        Raises:
            RepositoryFetchError: 當結構缺漏必填欄位時。
        """
        repositories_raw = payload.get("repositories")
        if repositories_raw is None:
            raise RepositoryFetchError("Cursor API 回傳缺少 repositories 欄位")
        if not isinstance(repositories_raw, Sequence) or isinstance(repositories_raw, (str, bytes)):
            raise RepositoryFetchError("Cursor API repositories 欄位格式錯誤")

        parsed: list[RepositoryPayload] = []
        for item in repositories_raw:
            if not isinstance(item, dict):
                raise RepositoryFetchError("Cursor API repositories 欄位必須為物件陣列")
            owner = item.get("owner")
            name = item.get("name")
            url = item.get("repository")
            if not all((owner, name, url)):
                raise RepositoryFetchError("Cursor API repositories 欄位缺少 owner/name/repository")
            parsed.append(RepositoryPayload(owner, name, url))
        return parsed

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        將資料庫中的時間字串轉換為時區化 datetime。

        Args:
            timestamp_str (str): SQLite created_at 字串

        Returns:
            datetime: 轉換後的 UTC 時間

        Examples:
            >>> service._parse_timestamp("2024-01-01 00:00:00")  # doctest: +SKIP
            datetime.datetime(2024, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)

        Raises:
            ValueError: 當字串無法解析時。
        """
        normalized = timestamp_str.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
