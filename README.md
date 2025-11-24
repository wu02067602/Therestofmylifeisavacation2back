# Therestofmylifeisavacation2back

基於 FastAPI 的背景輔助工具，提供註冊、登入與登出 API，並透過資料庫協調層統一封裝 SQLite 與 BigQuery 的使用方式。

## API 文件

### 註冊使用者
- 路徑：`POST /register`
- 說明：建立新帳號，需提供唯一的 `account` 與 `cursor_api_key`
- 成功回應：`201 Created`

請求範例：
```json
{
  "account": "demo-account",
  "password": "StrongPass!123",
  "cursor_api_key": "ck_live_xxx"
}
```

成功回應：
```json
{
  "success": true,
  "message": "註冊成功"
}
```

常見錯誤：
- `409 Conflict`：帳號或 `cursor_api_key` 重複
- `400 Bad Request`：欄位缺漏或為空

### 登入
- 路徑：`POST /login`
- 說明：驗證帳號密碼並產出有效 24 小時的 JWT
- 成功回應：`200 OK`

請求範例：
```json
{
  "account": "demo-account",
  "password": "StrongPass!123"
}
```

成功回應：
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "username": "demo-account",
  "userId": 1
}
```

常見錯誤：
- `401 Unauthorized`：帳號或密碼錯誤
- `400 Bad Request`：必填欄位為空

### 登出
- 路徑：`POST /logout`
- 說明：註銷 JWT Token，後續請求會被視為未授權
- 成功回應：`200 OK`

請求範例：
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

成功回應：
```json
{
  "success": true,
  "message": "登出成功"
}
```

常見錯誤：
- `401 Unauthorized`：Token 驗證失敗或已過期
- `409 Conflict`：Token 已被註銷
- `400 Bad Request`：Token 欄位缺漏

## 環境變數

| 變數 | 說明 | 預設值 |
| --- | --- | --- |
| `DB_BACKEND` | 使用的資料庫，支援 `sqlite` 與 `bigquery` | `sqlite` |
| `SQLITE_DB_PATH` | SQLite 檔案路徑（使用 sqlite 時有效） | `/workspace/auth.db` |
| `JWT_SECRET` | JWT 金鑰 | `cursor-dev-secret` |
| `JWT_ALGORITHM` | JWT 演算法 | `HS256` |
| `TOKEN_TTL_HOURS` | Token 有效時間（小時） | `24` |
| `CORS_ALLOW_ORIGINS` | 允許的 CORS 來源，逗號分隔 | `*` |

## 本地開發

1. 安裝依賴
   ```bash
   pip install -r requirements.txt
   ```
2. 啟動開發伺服器
   ```bash
   uvicorn app:app --reload --port 8000
   ```