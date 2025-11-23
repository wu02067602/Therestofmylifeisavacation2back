from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI()

# 加入 CORS 中間件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 允許所有來源，生產環境建議指定特定網域
    allow_credentials=True,
    allow_methods=["*"],  # 允許所有 HTTP 方法
    allow_headers=["*"],  # 允許所有標頭
)


class LoginRequest(BaseModel):
    account: str
    password: str


@app.post("/login")
async def login(login_request: LoginRequest):
    """
    接收帳號密碼並返回 true
    """
    # 這裡可以加入驗證邏輯，目前直接返回 true
    return {"success": True}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

