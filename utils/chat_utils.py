from inspect import cleandoc
from multiprocessing import Value
import re
from langchain_community.chat_models import ChatOllama
from langchain.prompts import PromptTemplate
import logging
from typing import List


# Setup app logger
logger = logging.getLogger(__name__)

# Langchain Ollama setup
llm = ChatOllama(model="deepseek-r1:1.5b")


def clean_llm_response(response:str) -> str:
    """
    Clean the LLM response by removing the <think> tags and extracting the final answer.

    Args:
        response (str): The raw response from the LLM.
    
    Returns:
        str: The cleaned response without <think> tags.
    """
    try:
        # Remove <think> tags and their conent
        cleaned = re.sub(r'<think>.*?<./think>\s*','', response)

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



def process_chat(query: str, history: List = None ) -> str:
    """
        Process a chat query using the Ollama LLM with optional chat history for context.

        Args:
            query (str): The user's query.
            history (list): List of dicts with 'query' and 'response' for previous chats.

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
                if not isinstance(chat,dict) or "query" not in chat or "response" not in chat:
                    logger.error(f"Invalid history item: {chat}")
                    raise ValueError("History item must be a dict with 'query' and response 'resposne' keys")
                history_text += f"User: {chat['query']}\nAssistant: {chat['response']}\n\n"
        logger.info(f"History context: {history_text}")

        # Create a prompt with context
        prompt_template = PromptTemplate(
            input_variables=["history","query"],
            template=(
                "You are a helpful assistant.\n"
                "Use the following conversation history for context (if any):\n"
                "{history}\n"
                "Answer the following question concisely: {query}"
            )
        )

        logger.info(f"Prompt template: {prompt_template}")
        format_prompt = prompt_template.format(history=history_text, query=query)
        logger.info(f"Formatted prompt: {format_prompt}")

        response = llm.invoke(format_prompt)

        if response is None:
            logger.warning("LLM response is None")
            raise ValueError("LLM invocation return none")

        answer = response.content if hasattr(response, 'content') else str(response)

        if not answer:
            logger.warning("LLM returned empty response")
            raise ValueError("LLM returned empty response")
        
        logger.info(f"LLM response: {answer}")

        cleaned_answer = clean_llm_response(answer)

        return cleaned_answer
        
    except Exception as e :
        logger.error(f"Error processing chat query: {str(e)}")
        raise Exception(f"Error processing chat query: {str(e)}")
