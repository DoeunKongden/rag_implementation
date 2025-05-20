RAG FastAPI Project
Overview
This project is a Retrieval-Augmented Generation (RAG) application built with FastAPI, SQLAlchemy, and LangChain. It provides a RESTful API for user authentication, chat session management, query processing with a language model (Ollama's deepseek-r1:1.5b), and file upload/deletion. The application stores user data, chat history, and file metadata in a PostgreSQL database and supports file-based context for queries (PDF, DOC, DOCX).
Features

User Authentication: Sign up and log in with JWT-based authentication.
Chat Sessions: Create and manage chat sessions with optional titles and associated files.
Query Processing: Process user queries with conversational history using LangChain and Ollama.
File Management: Upload, list, and delete files (PDF, DOC, DOCX) for use in RAG.
Database: PostgreSQL with SQLAlchemy ORM for persistent storage.
Logging: Comprehensive logging to app.log for debugging and monitoring.

Project Structure
rag-fastapi-project/
├── main.py              # FastAPI application with endpoints
├── utils/
│   ├── db_utils.py      # SQLAlchemy models and database utilities
│   ├── chat_utils.py    # LangChain integration for query processing
├── schemes/
│   ├── schema.py        # Pydantic models for API schemas
│   ├── pydantic_model.py # Pydantic model for user creation
├── uploaded_file/       # Directory for storing uploaded files
├── app.log              # Log file for application events
├── .env                 # Environment variables (not tracked)
├── README.md            # This file

Requirements

Python 3.8+

PostgreSQL

Ollama server with deepseek-r1:1.5b model

Dependencies (see requirements.txt or install manually):
pip install fastapi uvicorn sqlalchemy psycopg2-binary bcrypt python-jose[cryptography] python-dotenv langchain-community PyPDF2 python-docx



Setup Instructions

Clone the Repository:
git clone <repository-url>
cd rag-fastapi-project


Set Up Environment Variables: Create a .env file in the project root:
JWT_SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTE=30

Replace your-secret-key with a secure key (e.g., generated via openssl rand -hex 32).

Set Up PostgreSQL:

Install PostgreSQL and create a database named postgres.

Update the DATABASE_URL in db_utils.py if needed:
DATABASE_URL = "postgresql://username:password@localhost:5432/postgres"


Create database tables:
from utils.db_utils import Base, engine
Base.metadata.create_all(bind=engine)




Set Up Ollama:

Install Ollama: https://ollama.ai

Pull the deepseek-r1:1.5b model:
ollama pull deepseek-r1:1.5b


Start the Ollama server:
ollama serve




Install Dependencies:
pip install -r requirements.txt

Or manually install:
pip install fastapi uvicorn sqlalchemy psycopg2-binary bcrypt python-jose[cryptography] python-dotenv langchain-community PyPDF2 python-docx


Run the Application:
uvicorn main:app --reload

The API will be available at http://localhost:8000.


API Endpoints

Authentication:
POST /signup: Create a new user (requires UserCreate schema).
POST /login: Log in and receive a JWT token.


Chat Sessions:
POST /session: Create a chat session (returns ChatSessionResponse).


Chat:
POST /chat/: Process a query with optional chat session and file IDs (returns QueryResponse).
GET /history: Retrieve chat history for the authenticated user (returns list of ChatHistoryResponse).


Files:
POST /upload: Upload a PDF, DOC, or DOCX file (returns FileUploadResponse).
GET /files: List all files for the authenticated user (returns list of FileUploadResponse).
DELETE /files/{file_id}: Delete a specific file.



Example Usage

Sign Up:
curl -X POST "http://localhost:8000/signup" -H "Content-Type: application/json" -d '{"username": "testuser", "password": "securepassword", "profile_img": null, "user_bio": null}'


Log In:
curl -X POST "http://localhost:8000/login" -H "Content-Type: application/x-www-form-urlencoded" -d "username=testuser&password=securepassword"


Create Chat Session:
curl -X POST "http://localhost:8000/session" -H "Authorization: Bearer <jwt_token>" -H "Content-Type: application/json" -d '{"title": "My Chat"}'


Process Chat Query:
curl -X POST "http://localhost:8000/chat/" -H "Authorization: Bearer <jwt_token>" -H "Content-Type: application/json" -d '{"query": "Hello", "chat_session_id": null, "file_ids": null}'


Upload File:
curl -X POST "http://localhost:8000/upload" -H "Authorization: Bearer <jwt_token>" -F "file=@/path/to/document.pdf"



Notes

File Processing: File content extraction (PDF, DOC, DOCX) for RAG is not fully implemented. Update chat_utils.py to include PyPDF2 or python-docx for processing.
Timezone: All timestamps use UTC for consistency.
Logging: Logs are written to app.log for debugging.
Future Updates: Planned enhancements include full RAG functionality, additional endpoints (e.g., update/delete chat sessions), and improved file processing.

Contributing
This project is under active development. To contribute:

Fork the repository.
Create a feature branch (git checkout -b feature/your-feature).
Commit changes (git commit -m "Add your feature").
Push to the branch (git push origin feature/your-feature).
Open a pull request.

License
MIT License (to be added).
TODO

Implement file content extraction for RAG.
Add endpoints for updating and deleting chat sessions.
Enhance error handling and validation.
Add unit tests and API documentation (e.g., OpenAPI/Swagger).

