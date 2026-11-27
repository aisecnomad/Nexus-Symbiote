from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

@tool
def count_pending() -> str:
    """Count the public queue."""
    return "3"

queue_reader = create_react_agent(model="openai:gpt-4.1-mini", tools=[count_pending], name="CopperReader")
