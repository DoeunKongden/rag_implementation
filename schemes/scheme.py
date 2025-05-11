from pydantic import BaseModel
import datetime


class UserLoginRequest(BaseModel):
    username: str
    password: str


class QueryRequest(BaseModel):
    query: str


class QueryResponse(BaseModel):
    answer: str


class FileUploadResponse(BaseModel):
    file_id: int
    file_name: str
    file_path: str
    upload_timestamp: datetime

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True


class ChatHistoryResponse(BaseModel):
    chat_id: int
    user_id: int
    response: str
    timestamp: datetime

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True
