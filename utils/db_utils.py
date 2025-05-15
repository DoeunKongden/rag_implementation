import uuid

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt
import datetime
from datetime import  timedelta

DATABASE_URL = "postgresql://postgres:DeN112233@localhost:5432/langchain_miniproject"
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
    created_at = Column(DateTime, default=datetime.datetime.now())
    updated_at = Column(DateTime, default=datetime.datetime.now(), onupdate=datetime.datetime.now())


class Chat(Base):
    __tablename__ = "chat_tb"
    chat_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user_tb.user_id"))
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
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    db_user = User(
        username=user.username,
        user_password=hashed_password.decode('utf-8'),
        profile_img=user.profile_img,
        user_bio=user.user_bio
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def authenticate_user(db, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not bcrypt.checkpw(password.encode('utf-8'), user.user_password.encode('utf-8')):
        return False
    return user


def create_session(db, user_id: int, expire_in_minute: int = 30) -> str:
    session_id = str(uuid.uuid4())
    expired_at = datetime.datetime.now() + timedelta(minutes=expire_in_minute)
    db_session = Session(
        session_id=session_id,
        user_id=user_id,
        expired_at=expired_at
    )
    db.add(db_session)
    db.commit()
    return session_id
