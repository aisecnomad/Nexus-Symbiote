from pathlib import Path
from typing import TypedDict

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_chroma import Chroma
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition


class OrderState(TypedDict):
    messages: list


@tool
def lookup_order(order_id: str) -> str:
    """Look up a synthetic order by identifier."""
    return {"A001": "packed", "A002": "shipped"}.get(order_id, "unknown")


def build_order_router():
    model = ChatOpenAI(model="gpt-4o-mini")
    policy = Path("prompts/order_policy.md").read_text(encoding="utf-8")
    model_with_tools = model.bind_tools([lookup_order])
    embed = OpenAIEmbeddings(model="text-embedding-3-small")
    index = Chroma(collection_name="atlas_orders", embedding_function=embed)

    def route(state: OrderState):
        context = index.similarity_search("synthetic order guidance", k=1)
        messages = [("system", f"{policy}\n{context}"), *state["messages"]]
        return {"messages": [model_with_tools.invoke(messages)]}

    workflow = StateGraph(OrderState)
    workflow.add_node("route", route)
    workflow.add_node("tools", ToolNode([lookup_order]))
    workflow.add_edge(START, "route")
    workflow.add_conditional_edges("route", tools_condition, {"tools": "tools", "__end__": END})
    workflow.add_edge("tools", "route")
    return workflow.compile(name="atlas_order_router")


# Retired before this fixture's baseline: ChatOpenAI(model="gpt-3.5-turbo-0613")
