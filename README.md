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

使用說明：
1. 每次進入專案前先呼叫此 API，同步最新的通用規則文字供 Cursor 指令或背景任務使用。
2. `content` 欄位為純文字，建議維持 Markdown 清單的格式便於閱讀。
3. `lastUpdatedAt` 可用於快取判斷，當時間戳未變化時可跳過重複載入。

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

使用說明：
1. 建議在更新前先呼叫取得 API 取得目前內容，再由前端顯示並讓使用者覆寫。
2. 內容會被完整取代，若需要保留部分段落請自行在客戶端合併後再送出。
3. 回應中的 `lastUpdatedAt` 代表實際寫入時間，可同步更新 UI。

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

使用說明：
1. 建議在載入專案後立即呼叫此 API，將結果呈現在 UI 供使用者快速插入重複任務。
2. 任務內容為純文字，可作為 Cursor 背景任務或提示的候選清單。
3. 若需要依照不同分類顯示，可在前端根據字首或自訂規則區分。

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

使用說明：
1. 此 API 以「覆寫」方式運作，請務必在送出前合併前端最新排序與內容。
2. 當 `tasks` 傳入空陣列時代表清空所有常用任務。
3. 建議在成功回應後立即重新整理本地快取，避免顯示舊資料。

常見錯誤：
- `400 Bad Request`：`repositoryUrl` 為空、`tasks` 內含空字串或重複無法處理
- `404 Not Found`：帳號不存在

### 任務卡管理
任務卡 API 用於在專案內追蹤實際協作內容，並支援 WebSocket 即時通知。

#### 任務卡資料結構
`taskDescription` 欄位是一個 JSON Array，支援以下型態：

| type | 必填欄位 | 用途 |
| --- | --- | --- |
| `code_responsibility` | `file_name`, `class_name`, `responsibility` | 描述檔案或類別職責 |
| `modification` | `target`, `content` | 記錄修改目標與內容 |
| `reading` | `target`, `content` | 標記閱讀素材與期待理解重點 |
| `custom` | `narrative` | 其他自由敘述 |

#### 取得任務卡
- 路徑：`GET /accounts/{account}/task-cards?repositoryUrl=...`
- 目的：列出指定儲存庫的所有任務卡

成功回應：
```json
{
  "account": "demo-account",
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "cards": [
    {
      "cardId": 12,
      "userId": 3,
      "repositoryUrl": "https://github.com/your-org/your-repo",
      "taskName": "實作 task_cards API",
      "taskDescription": [
        {
          "type": "modification",
          "target": "app.py",
          "content": "新增 task cards REST API"
        }
      ],
      "taskStatus": "InProgress",
      "createdAt": "2025-01-01 10:30:00",
      "updatedAt": "2025-01-01 10:35:00"
    }
  ]
}
```

#### 建立任務卡
- 路徑：`POST /accounts/{account}/task-cards`
- 請求欄位：`repositoryUrl`, `taskName`, `taskDescription`, `taskStatus`

```json
{
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "taskName": "撰寫 README 任務說明",
  "taskDescription": [
    {
      "type": "reading",
      "target": "產品需求",
      "content": "確認 API 文件要求"
    }
  ],
  "taskStatus": "ToDo"
}
```

回應內容會回傳完整任務卡資料，包含 `cardId`、`createdAt` 與 `updatedAt`。

#### 更新任務卡
- 路徑：`PUT /accounts/{account}/task-cards/{card_id}`
- 可更新欄位：`taskName`, `taskDescription`, `taskStatus`（需同時帶上 `repositoryUrl`）

```json
{
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "taskStatus": "Done"
}
```

回應會回傳更新後的任務卡資料，若任務狀態或描述改變，系統會透過 WebSocket 廣播事件。

#### 刪除任務卡
- 路徑：`DELETE /accounts/{account}/task-cards/{card_id}?repositoryUrl=...`
- 成功時回傳 `204 No Content`

#### 任務卡即時通知 WebSocket
- 路徑：`GET ws://{host}/ws/task-cards?repositoryUrl=...`
- 事件 payload 範例：

```json
{
  "event": "task_card_updated",
  "repositoryUrl": "https://github.com/your-org/your-repo",
  "cardId": 12,
  "card": {
    "cardId": 12,
    "userId": 3,
    "repositoryUrl": "https://github.com/your-org/your-repo",
    "taskName": "實作 task_cards API",
    "taskDescription": [],
    "taskStatus": "Done",
    "createdAt": "2025-01-01 10:30:00",
    "updatedAt": "2025-01-01 10:45:00"
  }
}
```

若任務卡被刪除，`card` 會是 `null`，但 `cardId` 仍會保留，方便前端移除列表。

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