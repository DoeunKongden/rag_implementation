from pydantic import BaseModel
import datetime
from typing import Optional, List


class UserLoginRequest(BaseModel):
    username: str
    password: str


class QueryRequest(BaseModel):
    query: str
    chat_session_id: Optional[int] = None


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


class FileDeleteRequest(BaseModel):
    file_ids: List[int]


class FileDeleteResponse(BaseModel):
    file_id: int
    status: str
    message: str

class QueryWithFileRequest(BaseModel):
    query: str
    chat_session_id: int
    file_ids: Optional[List[int]] = None


class ChatSessionCreate(BaseModel):
    title: Optional[str] = None
    file_ids: Optional[List[int]] = None


class ChatSessionResponse(BaseModel):
    session_id: int
    user_id: int
    title: Optional[str]
    session_type: str
    updated_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True


class ChatSessionUpdate(BaseModel):
    title: str

