from multiprocessing import process
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
import os
import logging
from typing import Optional
from datetime import datetime, timedelta
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from schemes.scheme import QueryResponse, QueryRequest, ChatHistoryResponse, ChatSessionResponse, ChatSessionCreate
from models.pydantic_model import UserCreate
from utils.db_utils import create_user, get_db, authenticate_user, User, Chat, File as DBFile, get_chat_session, create_session, get_session_chats
from utils.chat_utils import process_chat
from typing import List
from schemes.scheme import FileUploadResponse
import uuid
import shutil

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(filename="app.log", level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize the FastAPI
app = FastAPI(title="RAG FastAPI Project")

# JWT Setting
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "a6b75603711065013bc5e97ff3d7837985e3cc8b63b1061e63944cab304fced2")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTE = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTE", 30))

# Document Direction
DOCUMENT_DIR = "./uploaded_file"
os.makedirs(DOCUMENT_DIR, exist_ok=True)

if not os.getenv("JWT_SECRET_KEY"):
    logger.warning("JWT_SECRET_KEY not set in environment, using default")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# JWT token creation
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTE)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.info(f"Created JWT token for user: {data.get('sub')}")
    return encoded_jwt


# Get current user from token
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.error("JWT token missing 'sub' claim")
            raise credentials_exception
        logger.debug(f"Decoded JWT token with username: {username}")
    except JWTError as e:
        logger.error(f"JWT decoding error: {str(e)}")
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        logger.error(f"User not found in database: {username}")
        raise credentials_exception
    logger.info(f"Authenticated user: {username}")
    return user


@app.post("/signup", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        logger.error(f"Signup failed: Username already registered: {user.username}")
        raise HTTPException(status_code=400, detail="Username already registered")
    created_user = create_user(db, user)
    logger.info(f"User created: {created_user.username}")
    return {"message": "User created successfully"}


@app.post("/login", tags=["Authentication"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        logger.error(f"Login failed: Incorrect username or password for {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTE)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    logger.info(f"Login successful: {user.username}")
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/session", response_model=ChatSessionResponse ,tags=["Chat Session"])
async def create_chat_session(request: ChatSessionCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        session_id = create_session(db, user.user_id, request.title)
        session = get_chat_session(db, session_id, user.user_id)
        return session
    except Exception as e:
        logger.error(f"Create chat session failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/chat/", response_model=QueryResponse, tags=["Chat"])
async def chat_endpoint(query: QueryRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        # Auto create chat session Id if not 
        chat_session_id = query.chat_session_id
        if not query.chat_session_id:
            chat_session_id = create_session(db,user.user_id, "New Chat Session")
            logger.info(f"Auto created chat session ID: {chat_session_id} for user {user.username}")
        
        # Verify session exist and belong to user
        session = get_chat_session(db,chat_session_id,user.user_id)
        if not session:
            logger.error(f"Chat session not found or not owned by user {user.username}: session id={chat_session_id}")
            raise HTTPException(status_code=404, detail="Chat session not found or not owned by user")
        
        # Get session chat history
        chats = get_session_chats(db,chat_session_id,user.user_id)
        history = [{"query":chat.query, "response":chat.response} for chat in chats]

        answer = process_chat(query.query, history)
        chat = Chat(
            user_id=user.user_id,
            chat_session_id=chat_session_id,
            query=query.query,
            response=answer
        )
        db.add(chat)
        db.commit()
        logger.info(f"Chat query processed by user {user.username}, session_id={chat_session_id}:{query.query}")
        print(f"Answer response from llm :{answer}")
        return QueryResponse(answer=answer)
            

    except Exception as e:
        logger.error(f"Chat endpoint error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history", response_model=List[ChatHistoryResponse], tags=["Chat"])
async def get_chat_history(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        chats = db.query(Chat).filter(Chat.user_id == user.user_id).order_by(Chat.timestamp.desc()).all()
        return chats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/upload", response_model=FileUploadResponse, tags=['Files'])
async def upload_file(file: UploadFile = File(...), user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    try:
        if not file.filename.lower().endswith((".pdf", ".docx", ".doc")):
            logger.error(f"Invalid file type upload by user {user.username} : {file.filename}")
            raise HTTPException(status_code=400, detail="Only PDF, DOC or DOCX file are allowed")

        #  Generate Unique filename
        file_extension = os.path.splitext(file.filename)[1]
        unique_filename = f"{user.user_id}_{uuid.uuid4()}{file_extension}"
        filepath = os.path.join(DOCUMENT_DIR, unique_filename)

        # Save file
        with open(filepath, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Save the DB metadata to the database
        db_file = DBFile(
            user_id=user.user_id,
            file_name=file.filename,
            file_path=filepath
        )

        db.add(db_file)
        db.commit()
        db.refresh(db_file)

        logger.info(f"File uploaded by user {user.username}: {file.filename} as {unique_filename}")
        return db_file

    except Exception as e:
        logger.error(f"File upload error by user {user.user_id}:{str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/files", response_model=List[FileUploadResponse], tags=["Files"])
async def get_all_file(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        files = db.query(DBFile).filter(DBFile.user_id == user.user_id).order_by(DBFile.upload_timestamp.desc()).all()
        logger.info(f"Retrieved {len(files)} files for user {user.username}")
        return files
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/files/{file_id}", tags=["Files"])
async def delete_file(file_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        # Fetch File
        db_file = db.query(DBFile).filter(DBFile.file_id == file_id, DBFile.user_id == user.user_id).first()
        if not db_file:
            logger.error(f"File not found or not owned by user {user.username}: file_id={file_id}")
            raise HTTPException(status_code=404, detail="File not found or not authorized")

        # Delete the existing file
        if os.path.exists(db_file.file_path):
            os.remove(db_file.file_path)
        else:
            logger.warning(f"File not found in file system: {db_file.file_path}")
        db.delete(db_file)
        db.commit()
        logger.info(f"File deleted by user {user.username}: file_id={file_id}, filename={db_file.file_name}")
        return {"message": "File deleted successfully"}
    except Exception as e:
        logger.error(f"File deletion error for user {user.username}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


