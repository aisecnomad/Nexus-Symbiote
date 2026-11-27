from crewai import Agent
from crewai.tools import tool

@tool("region_lookup")
def region_lookup() -> str:
    """Return a public region."""
    return "north"

region_reader = Agent(role="VioletCurator", goal="Summarize regions", backstory="A directory assistant.",
                      llm="gpt-4o-mini", tools=[region_lookup])
