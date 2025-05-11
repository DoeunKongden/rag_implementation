from langchain_community.chat_models import ChatOllama
from langchain.prompts import PromptTemplate

# Langchain Ollama setup
llm = ChatOllama(model="llama3.2")
prompt_template = PromptTemplate(
    input_variables=["query"],
    template=""""
    You are a helpful assistant. Answer the following question concisely: {query}
    """
)


def process_chat(query: str) -> str:
    """"
    Process a chat query using Ollama LLM and return a response

    Args:
        query (str) : The user's query.
    Return:
        str: The LLM's response.
    Raise:
        Exception: If the LLM invocation fail
    """
    try:
        formatted_prompt = prompt_template.format(query=query)
        response = llm.invoke(formatted_prompt)
        return response.content if hasattr(response, 'content') else str(response)
    except Exception as e:
        raise Exception(f"Error processing chat: {str(e)}")
