UNCHECKED_PLAN = """Before concluding, do the planned checks you have not attempted yet: \
{checks}. Then reply with your updated summary without a tool call."""

TOO_FEW_CALLS = """You have made {done} data-tool call(s); make at least {required} before \
concluding, for example the process tree, network or DNS activity, logons, persistence, or \
the reputation of what you found. Then reply with your updated summary without a tool call."""
