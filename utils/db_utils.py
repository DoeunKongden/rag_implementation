import datetime
import json
import uuid
from datetime import timedelta
from typing import List

import bcrypt
from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    create_engine,
    null,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = "postgresql://postgres:DeN112233@localhost:5432/postgres"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "user_tb"
    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    profile_img = Column(String, nullable=True)
    user_bio = Column(String, nullable=True)
    user_password = Column(String)


class ChatSession(Base):
    __tablename__ = "chat_session_tb"
    session_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user_tb.user_id"))
    title = Column(String, nullable=True)
    file_ids = Column(JSON, nullable=True)
    session_type = Column(String, nullable=False, default="normal")
    created_at = Column(DateTime, default=datetime.datetime.now())
    updated_at = Column(
        DateTime, default=datetime.datetime.now(), onupdate=datetime.datetime.now()
    )


class Chat(Base):
    __tablename__ = "chat_tb"
    chat_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user_tb.user_id"))
    chat_session_id = Column(Integer, ForeignKey("chat_session_tb.session_id"))
    query = Column(String)
    response = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow())


class File(Base):
    __tablename__ = "file_tb"
    file_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user_tb.user_id"))
    file_name = Column(String)
    file_path = Column(String)
    upload_timestamp = Column(DateTime, default=datetime.datetime.utcnow())


class Session(Base):
    __tablename__ = "session_tb"
    session_id = Column(String, primary_key=True)
    user_id = Column(Integer, ForeignKey("user_tb.user_id"))
    created_at = Column(DateTime, default=datetime.datetime.now())
    expires_at = Column(DateTime)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_user(db, user):
    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())
    db_user = User(
        username=user.username,
        user_password=hashed_password.decode("utf-8"),
        profile_img=user.profile_img,
        user_bio=user.user_bio,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def authenticate_user(db, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not bcrypt.checkpw(password.encode("utf-8"), user.user_password.encode("utf-8")):
        return False
    return user


def create_session(db, user_id: int, expire_in_minute: int = 30) -> str:
    session_id = str(uuid.uuid4())
    expired_at = datetime.datetime.now() + timedelta(minutes=expire_in_minute)
    db_session = Session(session_id=session_id, user_id=user_id, expired_at=expired_at)
    db.add(db_session)
    db.commit()
    return session_id


def get_user_by_session(db, session_id: str):
    session = db.query(Session).filter(Session.session_id == session_id).first()
    if not session:
        return None
    if session.expires_at < datetime.datetime.now():
        db.delete(session)
        db.commit()
        return None
    return db.query(User).filter(User.user_id == session.user_id).first()


def delete_session(db, session_id):
    session = db.query(Session).filter(Session.session_id == session_id).first()
    if session:
        db.delete(session)
        db.commit()


async def create_chat_session(
    db, user_id: int, title: str = None, file_ids: List[int] = None
) -> int:
    try:
        session_type = "file-based" if file_ids else "normal"
        db_session = ChatSession(
            user_id=user_id,
            title=title,
            file_ids=json.dumps(file_ids) if file_ids else None,
            session_type=session_type,
        )

        db.add(db_session)
        db.commit()
        db.refresh(db_session)
        logger.info(
            f"Create sesision type: {session_type} of chat session: {db_session.session_id}"
        )
        return db_session.session_id
    except Exception as e:
        logger.error(f"Fail to create chat session: {e}")
        raise e


def get_chat_session(db, session_id: int, user_id: int):
    return (
        db.query(ChatSession)
        .filter(ChatSession.session_id == session_id, ChatSession.user_id == user_id)
        .first()
    )


def update_chat_session(
    db, user_id: int, session_id: int, tittle: str, file_ids: list = None
):
    chat_session = (
        db.query(ChatSession)
        .filter(ChatSession.session_id == session_id, ChatSession.user_id == user_id)
        .first()
    )
    if chat_session:
        if tittle is not None:
            chat_session.title = tittle
        if file_ids is not None:
            chat_session.file_ids = json.dump(file_ids) if file_ids else None
        db.commit()
        return chat_session
    else:
        return None


def delete_chat_session(db, session_id: int, user_id: int):
    chat_session = (
        db.query(ChatSession)
        .filter(ChatSession.session_id == session_id, ChatSession.user_id == user_id)
        .first()
    )

    if chat_session:
        db.query(Chat).filter(Chat.chat_session_id == session_id).delete()
        db.delete(chat_session)
        db.commit()
        return True
    return False


def get_session_chats(db, session_id: int, user_id: int):
    session = (
        db.query(ChatSession)
        .filter(ChatSession.session_id == session_id, ChatSession.user_id == user_id)
        .first()
    )
    if not session:
        return []
    return (
        db.query(Chat)
        .filter(Chat.chat_session_id == session_id)
        .order_by(Chat.timestamp.asc())
        .all()
    )
