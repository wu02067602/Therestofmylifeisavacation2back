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

### 取得帳號可用的 Git 儲存庫
- 路徑：`GET /accounts/{account}/repositories`
- 說明：輸入已註冊的 `account`，回傳該使用者的 Cursor API Key 能存取的 GitHub 儲存庫清單。若資料庫中最近一次同步未超過 30 分鐘，會直接回傳快取資料；超過時才呼叫 Cursor API（受 1 次/分鐘、30 次/小時的速率限制）。
- 成功回應：`200 OK`

請求範例：
```http
GET /accounts/demo-account/repositories HTTP/1.1
Host: localhost:8000
```

成功回應：
```json
{
  "account": "demo-account",
  "lastSyncedAt": "2025-01-01 10:30:00",
  "repositories": [
    {
      "owner": "your-org",
      "name": "your-repo",
      "repository": "https://github.com/your-org/your-repo"
    },
    {
      "owner": "your-org",
      "name": "another-repo",
      "repository": "https://github.com/your-org/another-repo"
    }
  ]
}
```

常見錯誤：
- `400 Bad Request`：`account` 為空字串
- `404 Not Found`：帳號不存在
- `502 Bad Gateway`：Cursor API 回應錯誤或逾時
- `429 Too Many Requests`：Cursor API 告知超過速率限制（轉為 502 返回，可從日誌查看詳細原因）

### 取得通用規則
- 路徑：`GET /accounts/{account}/general-rule?repositoryUrl=...`
- 說明：回傳指定帳號與儲存庫對應的通用規則文字與最後更新時間
- 成功回應：`200 OK`

請求範例：
```http
GET /accounts/demo-account/general-rule?repositoryUrl=https://github.com/your-org/your-repo HTTP/1.1
Host: localhost:8000
```

成功回應：
```json
{
  "account": "demo-account",
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "content": "請務必依照 SOLID 原則開發",
  "lastUpdatedAt": "2025-01-01 10:30:00"
}
```

常見錯誤：
- `400 Bad Request`：`repositoryUrl` 為空或輸入格式錯誤
- `404 Not Found`：帳號不存在

### 更新通用規則
- 路徑：`PUT /accounts/{account}/general-rule`
- 說明：以覆寫方式更新指定帳號與儲存庫的通用規則
- 成功回應：`200 OK`

請求範例：
```json
{
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "content": "請務必依照 SOLID 原則開發"
}
```

成功回應：
```json
{
  "account": "demo-account",
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "content": "請務必依照 SOLID 原則開發",
  "lastUpdatedAt": "2025-01-01 10:30:00"
}
```

常見錯誤：
- `400 Bad Request`：`repositoryUrl` 或 `content` 為空
- `404 Not Found`：帳號不存在

### 取得常用任務
- 路徑：`GET /accounts/{account}/common-tasks?repositoryUrl=...`
- 說明：取得指定帳號與儲存庫所儲存的常用任務清單
- 成功回應：`200 OK`

請求範例：
```http
GET /accounts/demo-account/common-tasks?repositoryUrl=https://github.com/your-org/your-repo HTTP/1.1
Host: localhost:8000
```

成功回應：
```json
{
  "account": "demo-account",
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "tasks": [
    "同步最新 repositories 清單",
    "檢查 README 是否更新"
  ]
}
```

常見錯誤：
- `400 Bad Request`：`repositoryUrl` 為空
- `404 Not Found`：帳號不存在

### 更新常用任務
- 路徑：`PUT /accounts/{account}/common-tasks`
- 說明：以覆寫方式更新指定帳號與儲存庫的常用任務；未包含於請求中的任務會被刪除
- 成功回應：`200 OK`

請求範例：
```json
{
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "tasks": [
    "同步最新 repositories 清單",
    "檢查 README 是否更新"
  ]
}
```

成功回應：
```json
{
  "account": "demo-account",
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "tasks": [
    "同步最新 repositories 清單",
    "檢查 README 是否更新"
  ]
}
```

常見錯誤：
- `400 Bad Request`：`repositoryUrl` 為空、`tasks` 內含空字串或重複無法處理
- `404 Not Found`：帳號不存在

### 任務卡資料結構
- `taskDescription` 是一個 JSON 陣列，每個元素必須包含 `type` 欄位，支援 `code_responsibility`、`modification`、`reading`、`custom`
- `code_responsibility` 需要 `file_name`、`class_name`、`responsibility`，可選 `notes`
- `modification` 與 `reading` 需要 `target` 與 `content`，可選 `notes`
- `custom` 需要 `narrative`
- `taskStatus` 僅允許 `ToDo`、`InProgress`、`Done`

### 取得任務卡
- 路徑：`GET /accounts/{account}/task-cards?repositoryUrl=...`
- 說明：回傳指定帳號的任務卡列表。`repositoryUrl` 可省略，省略時回傳所有任務卡
- 成功回應：

```json
{
  "account": "demo-account",
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "taskCards": [
    {
      "cardId": 12,
      "repositoryUrl": "https://github.com/your-org/your-repo",
      "taskName": "規劃登入流程",
      "taskDescription": [
        {
          "type": "code_responsibility",
          "file_name": "auth.py",
          "class_name": "LoginManager",
          "responsibility": "驗證帳密",
          "notes": "需確認 token TTL"
        }
      ],
      "taskStatus": "InProgress",
      "createdAt": "2025-01-01 10:00:00",
      "updatedAt": "2025-01-01 11:00:00"
    }
  ]
}
```

### 新增任務卡
- 路徑：`POST /accounts/{account}/task-cards`
- 說明：建立新的任務卡並立即透過 WebSocket 廣播
- 成功回應：`201 Created`
- 請求範例：

```json
{
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "taskName": "建立任務卡 API",
  "taskDescription": [
    {
      "type": "modification",
      "target": "app.py",
      "content": "新增 REST 與 WebSocket 端點",
      "notes": "需注意 CORS 設定"
    },
    {
      "type": "reading",
      "target": "Cursor API 文件",
      "content": "確認儲存庫取得限制"
    }
  ],
  "taskStatus": "ToDo"
}
```

### 更新任務卡
- 路徑：`PUT /accounts/{account}/task-cards/{card_id}`
- 說明：可以選擇要更新的欄位，至少需提供一個欄位
- 請求範例：

```json
{
  "taskStatus": "Done",
  "taskDescription": [
    {
      "type": "custom",
      "narrative": "所有子任務均已完成"
    }
  ]
}
```

- 成功回應：回傳更新後的整張任務卡
- 常見錯誤：
  - `400 Bad Request`：未提供任何欄位、描述格式錯誤
  - `404 Not Found`：帳號或任務卡不存在

### 刪除任務卡
- 路徑：`DELETE /accounts/{account}/task-cards/{card_id}`
- 說明：刪除指定任務卡，回傳 `{"success": true}`
- 常見錯誤：
  - `404 Not Found`：任務卡不存在

### 任務卡 WebSocket
- 路徑：`GET /ws/task-cards`（WebSocket）
- 說明：伺服器會在任務卡新增、更新、刪除時廣播事件
- 訊息格式：

```json
{
  "event": "task_card.updated",
  "account": "demo-account",
  "card": {
    "cardId": 12,
    "repositoryUrl": "https://github.com/your-org/your-repo",
    "taskName": "規劃登入流程",
    "taskDescription": [],
    "taskStatus": "InProgress",
    "createdAt": "2025-01-01 10:00:00",
    "updatedAt": "2025-01-01 11:05:00"
  }
}
```

- `event` 可能值：`task_card.created`、`task_card.updated`、`task_card.deleted`
- `task_card.deleted` 僅保證提供 `cardId` 與 `repositoryUrl`

## 環境變數

| 變數 | 說明 | 預設值 |
| --- | --- | --- |
| `DB_BACKEND` | 使用的資料庫，支援 `sqlite` 與 `bigquery` | `sqlite` |
| `SQLITE_DB_PATH` | SQLite 檔案路徑（使用 sqlite 時有效） | `/workspace/auth.db` |
| `JWT_SECRET` | JWT 金鑰 | `cursor-dev-secret` |
| `JWT_ALGORITHM` | JWT 演算法 | `HS256` |
| `TOKEN_TTL_HOURS` | Token 有效時間（小時） | `24` |
| `CORS_ALLOW_ORIGINS` | 允許的 CORS 來源，逗號分隔 | `*` |
| `CURSOR_API_BASE_URL` | Cursor API 根網址 | `https://api.cursor.com` |
| `CURSOR_API_TIMEOUT_SECONDS` | 呼叫 Cursor API 的逾時秒數（需為正數） | `30` |
| `REPOSITORY_CACHE_TTL_MINUTES` | 儲存庫快取的有效分鐘數（需為正整數） | `30` |

## 本地開發

1. 安裝依賴
   ```bash
   pip install -r requirements.txt
   ```
2. 啟動開發伺服器
   ```bash
   uvicorn app:app --reload --port 8000
   ```