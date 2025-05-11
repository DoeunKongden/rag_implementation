from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt
import datetime

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
