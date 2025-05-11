from pydantic import BaseModel
from typing import Optional
import datetime


class UserCreate(BaseModel):
    username: str
    password: str
    profile_img: Optional[str] = None
    user_bio: Optional[str] = None

    class Config:
        from_attributes = True
        arbitrary_types_allowed = True



