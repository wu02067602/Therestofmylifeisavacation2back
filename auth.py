"""
登入註冊模組，負責處理帳號註冊、登入與登出。
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from database import (
    DatabaseGateway,
    TokenAlreadyRevokedError,
    UserRecord,
)

logger = logging.getLogger(__name__)


class AccountAlreadyExistsError(ValueError):
    """
    當帳號重複時拋出的錯誤。

    Args:
        message (str): 錯誤訊息

    Returns:
        None.

    Examples:
        >>> raise AccountAlreadyExistsError("帳號重複")
        Traceback (most recent call last):
        ...
        AccountAlreadyExistsError: 帳號重複

    Raises:
        None.
    """


class CursorKeyAlreadyExistsError(ValueError):
    """
    當 Cursor API Key 重複時拋出的錯誤。

    Args:
        message (str): 錯誤訊息

    Returns:
        None.

    Examples:
        >>> raise CursorKeyAlreadyExistsError("Key 重複")
        Traceback (most recent call last):
        ...
        CursorKeyAlreadyExistsError: Key 重複

    Raises:
        None.
    """


class InvalidCredentialsError(ValueError):
    """
    當帳號或密碼錯誤時拋出的錯誤。

    Args:
        message (str): 錯誤訊息

    Returns:
        None.

    Examples:
        >>> raise InvalidCredentialsError("登入失敗")
        Traceback (most recent call last):
        ...
        InvalidCredentialsError: 登入失敗

    Raises:
        None.
    """


class AuthenticationError(RuntimeError):
    """
    其他驗證相關錯誤。

    Args:
        message (str): 錯誤訊息

    Returns:
        None.

    Examples:
        >>> raise AuthenticationError("驗證失敗")
        Traceback (most recent call last):
        ...
        AuthenticationError: 驗證失敗

    Raises:
        None.
    """


class LoginManager:
    """
    處理登入、註冊、登出的服務類別。

    Args:
        database (DatabaseGateway): 資料庫協調層
        jwt_secret (str): JWT 金鑰
        jwt_algorithm (str): JWT 演算法
        token_ttl_hours (int): Token 有效時間（小時）

    Returns:
        None.

    Examples:
        >>> manager = LoginManager(db, "secret")

    Raises:
        ValueError: 當輸入參數不合法時。
    """

    def __init__(
        self,
        database: DatabaseGateway,
        jwt_secret: str,
        jwt_algorithm: str = "HS256",
        token_ttl_hours: int = 24,
    ) -> None:
        """
        初始化 LoginManager。

        Args:
            database (DatabaseGateway): 資料庫協調層
            jwt_secret (str): JWT 金鑰
            jwt_algorithm (str): JWT 演算法，預設 HS256
            token_ttl_hours (int): Token 有效小時數

        Returns:
            None.

        Examples:
            >>> LoginManager(db, "secret")

        Raises:
            ValueError: Token 時效或金鑰無效時。
        """
        if not isinstance(database, DatabaseGateway):
            raise ValueError("database 參數必須實作 DatabaseGateway")
        if not jwt_secret:
            raise ValueError("JWT Secret 不可為空")
        if token_ttl_hours <= 0:
            raise ValueError("Token 時效必須為正整數")

        self._database = database
        self._jwt_secret = jwt_secret
        self._jwt_algorithm = jwt_algorithm
        self._token_ttl_hours = token_ttl_hours

    def register_user(self, account: str, password: str, cursor_api_key: str) -> bool:
        """
        註冊新使用者。

        Args:
            account (str): 帳號
            password (str): 密碼原文
            cursor_api_key (str): Cursor API Key

        Returns:
            bool: 註冊成功回傳 True

        Examples:
            >>> manager.register_user("demo", "pass", "key")
            True

        Raises:
            AccountAlreadyExistsError: 帳號重複時。
            CursorKeyAlreadyExistsError: Cursor API Key 重複時。
            DatabaseError: 資料庫操作失敗時。
            ValueError: 欄位為空時。
        """
        self._validate_registration_input(account, password, cursor_api_key)
        if self._database.get_user_by_account(account):
            logger.warning("帳號已存在: account=%s", account)
            raise AccountAlreadyExistsError("帳號已存在")
        if self._database.get_user_by_cursor_key(cursor_api_key):
            logger.warning("Cursor API Key 已存在: cursor_api_key=%s", cursor_api_key)
            raise CursorKeyAlreadyExistsError("Cursor API Key 已存在")

        hashed_password = self._hash_password(password)
        self._database.create_user(account, hashed_password, cursor_api_key)
        return True

    def login(self, account: str, password: str) -> Dict[str, str | int]:
        """
        進行登入並產生 JWT Token。

        Args:
            account (str): 帳號
            password (str): 密碼原文

        Returns:
            Dict[str, str | int]: 包含 accessToken、username、userId

        Examples:
            >>> manager.login("demo", "pass")
            {'accessToken': 'jwt', 'username': 'demo', 'userId': 1}

        Raises:
            InvalidCredentialsError: 當帳號或密碼不正確時。
            DatabaseError: 查詢資料庫失敗時。
            ValueError: 欄位為空時。
        """
        self._validate_login_input(account, password)
        hashed_password = self._hash_password(password)
        user = self._database.get_user_by_credentials(account, hashed_password)
        if not user:
            logger.warning("登入失敗，帳號或密碼錯誤: account=%s", account)
            raise InvalidCredentialsError("帳號或密碼錯誤")

        access_token = self._generate_token(user)
        return {
            "accessToken": access_token,
            "username": user.account,
            "userId": user.id,
        }

    def logout(self, access_token: str) -> bool:
        """
        註銷 JWT Token，完成登出。

        Args:
            access_token (str): JWT 字串

        Returns:
            bool: 成功註銷回傳 True

        Examples:
            >>> manager.logout("token")
            True

        Raises:
            AuthenticationError: Token 驗證失敗時。
            TokenAlreadyRevokedError: Token 已被註銷時。
            DatabaseError: 寫入資料庫失敗時。
            ValueError: Token 為空時。
        """
        if not access_token:
            raise ValueError("Token 不可為空")
        self._decode_token(access_token)
        if self._database.is_token_revoked(access_token):
            logger.warning("Token 已被註銷: token=%s", access_token)
            raise TokenAlreadyRevokedError("Token 已被註銷")
        self._database.revoke_token(access_token)
        return True

    def _hash_password(self, password: str) -> str:
        """
        使用 SHA-256 雜湊密碼。

        Args:
            password (str): 密碼原文

        Returns:
            str: 雜湊後字串

        Examples:
            >>> manager._hash_password("pass")  # doctest: +ELLIPSIS
            '1c8bfe8f...'

        Raises:
            ValueError: 密碼為空時。
        """
        if not password:
            raise ValueError("密碼不可為空")
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _generate_token(self, user: UserRecord) -> str:
        """
        產生 JWT Token。

        Args:
            user (UserRecord): 使用者資料

        Returns:
            str: JWT Token

        Examples:
            >>> manager._generate_token(UserRecord(1, "demo", "pwd", "key", "c", "u"))  # doctest: +ELLIPSIS
            'eyJ...'

        Raises:
            None.
        """
        expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=self._token_ttl_hours)
        payload = {
            "sub": str(user.id),
            "account": user.account,
            "cursorApiKey": user.cursor_api_key,
            "exp": expires_at,
        }
        return jwt.encode(payload, self._jwt_secret, algorithm=self._jwt_algorithm)

    def _decode_token(self, token: str) -> Dict[str, str]:
        """
        驗證並解析 JWT Token。

        Args:
            token (str): JWT 字串

        Returns:
            Dict[str, str]: Token 負載資料

        Examples:
            >>> manager._decode_token("token")  # doctest: +SKIP

        Raises:
            AuthenticationError: Token 失效或格式錯誤時。
        """
        try:
            return jwt.decode(token, self._jwt_secret, algorithms=[self._jwt_algorithm])
        except ExpiredSignatureError as exc:
            logger.warning("Token 已過期: %s", exc)
            raise AuthenticationError("Token 已過期") from exc
        except InvalidTokenError as exc:
            logger.warning("Token 驗證失敗: %s", exc)
            raise AuthenticationError("Token 驗證失敗") from exc

    def _validate_registration_input(self, account: str, password: str, cursor_api_key: str) -> None:
        """
        驗證註冊輸入值。

        Args:
            account (str): 帳號
            password (str): 密碼
            cursor_api_key (str): Cursor API Key

        Returns:
            None.

        Examples:
            >>> manager._validate_registration_input("a", "b", "c")

        Raises:
            ValueError: 任一輸入為空時。
        """
        if not account:
            raise ValueError("account 不可為空")
        if not password:
            raise ValueError("password 不可為空")
        if not cursor_api_key:
            raise ValueError("cursor_api_key 不可為空")

    def _validate_login_input(self, account: str, password: str) -> None:
        """
        驗證登入輸入值。

        Args:
            account (str): 帳號
            password (str): 密碼

        Returns:
            None.

        Examples:
            >>> manager._validate_login_input("demo", "pwd")

        Raises:
            ValueError: 任一輸入為空時。
        """
        if not account:
            raise ValueError("account 不可為空")
        if not password:
            raise ValueError("password 不可為空")
