from csv import reader
from inspect import cleandoc
from multiprocessing import Value
import re
from docx import Document
from langchain_community.chat_models import ChatOllama
from langchain.prompts import PromptTemplate
import logging
from typing import List
import PyPDF2
from langchain_core.callbacks import file


# Setup app logger
logger = logging.getLogger(__name__)

# Langchain Ollama setup
llm = ChatOllama(model="deepseek-r1:1.5b")


def clean_llm_response(response: str) -> str:
    """
    Clean the LLM response by removing the <think> tags and extracting the final answer.

    Args:
        response (str): The raw response from the LLM.

    Returns:
        str: The cleaned response without <think> tags.
    """
    try:
        # Remove <think> tags and their conent
        cleaned = re.sub(r"<think>.*?<./think>\s*", "", response)

        # Timmed whitespace with newlines
        cleaned = cleaned.strip()

        if not cleaned:
            logger.warning(f"Cleaned LLM response is empty")
            raise ValueError("Cleaned LLM response is empty")

        logger.debug(f"Cleaned LLM response: {cleaned}")
        return cleaned

    except Exception as e:
        logger.error(f"Error cleaning LLM response: {str(e)}")
        raise ValueError(f"Error cleaning LLM response: {str(e)}")


def extract_file_content(file_path: str):
    """
    Extract text content from a file (PDF or docx)
        Args:
        file_path (str): Path to the file.

    Returns:
        str: Extracted text content.
    """
    try:
        if file_path.lower().endswith(".pdf"):
            with open(file_path, "rb") as file:
                reader = PyPDF2.PdfReader(file)
                text = ""
                for page in reader.pages:
                    text += page.extract_text() + "\n"
                return text
        elif file_path.lower().endswith((".docx", ".doc")):
            doc = Document(file_path)
            text = ""
            for para in doc.paragraphs:
                text += para.text + "\nt+"
            return text

        else:
            logger.error(f"Error extracting content from file path : {file_path}")
            return ""

    except Exception as e:
        logger.error(
            f"Error extracting content from file : {file_path} error : {str(e)}"
        )
        return ""


def process_chat(query: str, history: List = None, file_paths: List[str] = None) -> str:
    """
    Process a chat query using the Ollama LLM with optional chat history for context.

    Args:
        query (str): The user's query.
        history (list): List of dicts with 'query' and 'response' for previous chats.
        file_paths (list): List of file paths to include in the prompt.
    Returns:
        str: The LLM's response.

    Raises:
        Exception: If the LLM invocation fails.
    """
    try:
        logger.info(f"Processing chat query: {query}")
        # Building a history context
        history_text = ""
        if history:
            for chat in history:
                if (
                    not isinstance(chat, dict)
                    or "query" not in chat
                    or "response" not in chat
                ):
                    logger.error(f"Invalid history item: {chat}")
                    raise ValueError(
                        "History item must be a dict with 'query' and response 'resposne' keys"
                    )
                history_text += (
                    f"User: {chat['query']}\nAssistant: {chat['response']}\n\n"
                )
        logger.info(f"History context: {history_text}")

        # Extracting file content if provided
        file_content = ""
        if file_paths:
            for file_path in file_paths:
                content = extract_file_content(file_path)
                if content:
                    file_content += f"\nFile content from {file_path}:\n{content}\n"
            logger.info(f"File content included: {file_content}")

        # Create a prompt with context
        prompt_template = PromptTemplate(
            input_variables=["history", "file_content", "query"],
            template=(
                "You are a helpful assistant.\n"
                "Use the following conversation history for context (if any):\n"
                "{history}\n"
                "Use the following file content for context (if any):\n"
                "{file_content}\n"
                "Answer the following question concisely: {query}"
            ),
        )

        logger.info(f"Prompt template: {prompt_template}")
        format_prompt = prompt_template.format(history=history_text, file_content=file_content,query=query)
        logger.info(f"Formatted prompt: {format_prompt}")

        response = llm.invoke(format_prompt)

        if response is None:
            logger.warning("LLM response is None")
            raise ValueError("LLM invocation return none")

        answer = response.content if hasattr(response, "content") else str(response)

        if not answer:
            logger.warning("LLM returned empty response")
            raise ValueError("LLM returned empty response")

        logger.info(f"LLM response: {answer}")

        cleaned_answer = clean_llm_response(answer)

        return cleaned_answer

    except Exception as e:
        logger.error(f"Error processing chat query: {str(e)}")
        raise Exception(f"Error processing chat query: {str(e)}")
