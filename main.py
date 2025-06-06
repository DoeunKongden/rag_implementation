import logging
import os
import shutil
import uuid
from datetime import datetime, timedelta
from multiprocessing import process
from typing import List, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, responses, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from langchain_core.messages import chat
from langchain_core.runnables import history
from sqlalchemy.orm import Session, query, session

from models.pydantic_model import UserCreate
from schemes.scheme import (
    ChatHistoryResponse,
    ChatSessionCreate,
    ChatSessionResponse,
    FileUploadResponse,
    QueryRequest,
    QueryResponse,
    QueryWithFileRequest,
)
from utils.chat_utils import process_chat
from utils.db_utils import (
    Chat,
    ChatSession,
)
from utils.db_utils import File as DBFile
from utils.db_utils import (
    User,
    authenticate_user,
    create_chat_session,
    create_user,
    get_chat_session,
    get_db,
    get_session_chats,
)

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(filename="app.log", level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize the FastAPI
app = FastAPI(title="RAG FastAPI Project")

# JWT Setting
SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY", "a6b75603711065013bc5e97ff3d7837985e3cc8b63b1061e63944cab304fced2"
)
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
async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        logger.debug(f"Decoded JWT token with username: {username}")
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            logger.error(f"User not found in database: {username}")
            raise credentials_exception
        logger.info(f"Authenticated user: {username}")
        logger.info(
            f"Authenticated User Object: type={type(user)}, user_id={user.user_id}"
        )
        return user
    except JWTError as e:
        logger.error(f"JWT decoding error: {str(e)}")
        raise credentials_exception


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
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        logger.error(
            f"Login failed: Incorrect username or password for {form_data.username}"
        )
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


@app.post("/session", response_model=ChatSessionResponse, tags=["Chat Session"])
async def create_chat_session_endpoint(
    request: ChatSessionCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        # Validate file_ids if provided
        valid_file_ids = []
        if request.file_ids:
            # remove invalid file ids
            filtered_file_ids = [fid for fid in request.file_ids if fid > 0]
            if filtered_file_ids:
                # check if file exist and belong to a user
                valid_files = (
                    db.query(DBFile)
                    .filter(
                        DBFile.file_id.in_(filtered_file_ids),
                        DBFile.user_id == user.user_id,
                    )
                    .all()
                )
                valid_file_ids = [f.file_id for f in valid_files]
                if not valid_file_ids:
                    logger.error(
                        f"No valid file_ids for user {user.username}: {request.file_ids}"
                    )
                    raise HTTPException(
                        status_code=400,
                        detail="No valid file IDs provided or files not owned by user",
                    )
                if len(valid_file_ids) != len(filtered_file_ids):
                    logger.warning(
                        f"Some file_ids are invalid for user {user.username}: {request.file_ids}"
                    )
        else:
            logger.info(
                f"Ignoring invalid file_ids for user {user.username}: {request.file_ids}"
            )

        # Await for the create_chat_session function to return the session_id
        session_id = await create_chat_session(
            db, user.user_id, request.title, valid_file_ids
        )
        session = get_chat_session(db, session_id, user.user_id)
        if not session:
            logger.error(f"Failed to create chat session for user {user.username}")
            raise HTTPException(status_code=400, detail="Failed to create chat session")

        logger.info(
            f"{session.session_type.capitalize()} chat session created: session_id={session_id}, user={user.username}, title={request.title}"
        )

        return ChatSessionResponse(
            session_id=session.session_id,
            user_id=session.user_id,
            title=session.title,
            created_at=session.created_at,
            updated_at=session.updated_at,
            session_type=session.session_type,
        )
    except ValueError as ve:
        logger.error(f"Value error in chat session creation: {str(ve)}")
        raise HTTPException(status_code=400, detail=str(ve))

    except Exception as e:
        logger.error(f"Create chat session failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@app.get(
    "/sessions",
    response_model=List[ChatSessionResponse],
    tags=["Chat Session"],
    summary="Get all chat sessions",
)
async def get_all_chat_sessions(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    try:
        sessions = (
            db.query(ChatSession)
            .filter(ChatSession.user_id == user.user_id)
            .order_by(ChatSession.created_at.desc())
            .all()
        )

        logger.info(f"Retrieved {len(sessions)} sessions for user {user.username}")

        return [
            ChatSessionResponse(
                session_id=session.session_id,
                user_id=session.user_id,
                title=session.title,
                created_at=session.created_at,
                updated_at=session.updated_at,
                session_type=session.session_type,
            )
            for session in sessions
        ]
    except Exception as e:
        logger.error(
            f"Failed to retrieve chat session for user {user.username} : {str(e)}"
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/query", response_model=QueryResponse, tags=["Query"])
async def process_query(
    request: QueryRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        # Fetch chat history if chat session ID is provided
        history = []
        if request.chat_session_id:
            session = get_chat_session(db, request.chat_session_id, user.user_id)
            if not session:
                logger.error(
                    f"Chat session : {request.chat_session_id} not found for user {user.user_id}"
                )
                raise HTTPException(status_code=404, detail="Chat Session not found")
            chats = get_session_chats(db, request.chat_session_id, user.user_id)
            history = [
                {"query": chat.query, "response": chat.response} for chat in chats
            ]
            logger.info(
                f"Retrieved {len(history)} chat history items for session_id={request.chat_session_id}, user={user.username}"
            )

            # Process the user query with an LLM
            response = process_chat(request.query, history)

            # Save the query and response to the Chat table
        db_chat = Chat(
            user_id=user.user_id,
            chat_session_id=request.chat_session_id,
            query=request.query,
            response=response,
        )
        db.add(db_chat)
        db.commit()

        logger.info(f"Query processed for user {user.username}: {request.query}")
        return QueryResponse(answer=response)
    except Exception as e:
        logger.error(f"Processing failed for user: {user.username} : {str(e)})")
        return HTTPException(status_code=500, detail=str(e))


@app.post("/query_with_file", response_model=QueryResponse, tags=["Query"])
async def process_query_with_file(
    request: QueryWithFileRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        # Validate the chat session
        chat_session = get_chat_session(db, request.chat_session_id, user.user_id)
        if not chat_session:
            logger.error(
                f"Chat session not found for user:{user.username} session:{request.chat_session_id}"
            )
            return QueryResponse(answer="Error: Chat session not found")

        # Fetch Chat history
        history = []
        chats = get_session_chats(db, request.chat_session_id, user.user_id)
        history = [{"query": chat.query, "response": chat.response} for chat in chats]

        logger.info(
            f"Retrieved {len(history)} chat history item from chat session {request.chat_session_id} , user:{user.username}"
        )

        # Fetch file path if file id is provided
        file_paths = []
        if request.file_ids:
            files = (
                db.query(DBFile)
                .filter(
                    DBFile.file_id.in_(request.file_ids), DBFile.user_id == user.user_id
                )
                .all()
            )
            # Map the each file path got from database into the array of file path
            file_paths = [file.file_path for file in files]
            if len(file_paths) != len(request.file_ids):
                logger.warning(f"Some files_id are invalid for user {user.username}:{request.file_ids}")
            
            logger.info(f"Retrieved {len(file_paths)} file path for user {user.username}")

            # Process the query with file with the LLM
            resposne = process_chat(request.query, history, file_paths)

            # Save the query with the LLM into the ChatTable
            db_chat = Chat(
                user_id=user.user_id,
                chat_session_id=request.chat_session_id,
                query=request.query,
                response=resposne,
            )
            db.add(db_chat)
            db.commit()
            logger.info(f"Query with file processed for user {user.username}:{request.query}")
            return QueryResponse(answer=resposne)

    except Exception as e:
        print("error", str(e))


@app.post("/upload", response_model=FileUploadResponse, tags=["Files"])
async def upload_file(
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        if not file.filename.lower().endswith((".pdf", ".docx", ".doc")):
            logger.error(
                f"Invalid file type upload by user {user.username} : {file.filename}"
            )
            raise HTTPException(
                status_code=400, detail="Only PDF, DOC or DOCX file are allowed"
            )

        #  Generate Unique filename
        file_extension = os.path.splitext(file.filename)[1]
        unique_filename = f"{user.user_id}_{uuid.uuid4()}{file_extension}"
        filepath = os.path.join(DOCUMENT_DIR, unique_filename)

        # Save file
        with open(filepath, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Save the DB metadata to the database
        db_file = DBFile(
            user_id=user.user_id, file_name=file.filename, file_path=filepath
        )

        db.add(db_file)
        db.commit()
        db.refresh(db_file)

        logger.info(
            f"File uploaded by user {user.username}: {file.filename} as {unique_filename}"
        )
        return db_file

    except Exception as e:
        logger.error(f"File upload error by user {user.user_id}:{str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/files", response_model=List[FileUploadResponse], tags=["Files"])
async def get_all_file(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    try:
        files = (
            db.query(DBFile)
            .filter(DBFile.user_id == user.user_id)
            .order_by(DBFile.upload_timestamp.desc())
            .all()
        )
        logger.info(f"Retrieved {len(files)} files for user {user.username}")
        return files
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/files/{file_id}", tags=["Files"])
async def delete_file(
    file_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    try:
        # Fetch File
        db_file = (
            db.query(DBFile)
            .filter(DBFile.file_id == file_id, DBFile.user_id == user.user_id)
            .first()
        )
        if not db_file:
            logger.error(
                f"File not found or not owned by user {user.username}: file_id={file_id}"
            )
            raise HTTPException(
                status_code=404, detail="File not found or not authorized"
            )

        # Delete the existing file
        if os.path.exists(db_file.file_path):
            os.remove(db_file.file_path)
        else:
            logger.warning(f"File not found in file system: {db_file.file_path}")
        db.delete(db_file)
        db.commit()
        logger.info(
            f"File deleted by user {user.username}: file_id={file_id}, filename={db_file.file_name}"
        )
        return {"message": "File deleted successfully"}
    except Exception as e:
        logger.error(f"File deletion error for user {user.username}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
