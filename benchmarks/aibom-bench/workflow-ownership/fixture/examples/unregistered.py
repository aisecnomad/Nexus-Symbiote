from langchain_core.tools import tool


@tool
def sample_order_lookup(order_id: str) -> str:
    """Return a sample response for an order identifier."""
    return f"Sample response for {order_id}"
