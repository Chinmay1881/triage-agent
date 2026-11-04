CRITIC = """Review this investigation before it concludes. Was a harmless explanation left \
unchecked? Was an obvious check skipped, such as the parent process and its signer, the \
user's role, reputation of hashes, IPs and domains, or related network and persistence \
activity? Set reopen to true only if a missing check could change the conclusion and can be \
done with these tools: {tools}. Name at most 3 checks, each with its tool. {budget_left} tool \
calls are left."""

REOPEN = """A reviewer asked for more checks before concluding: {checks}. Do them if they \
help, then reply with your updated summary without a tool call."""
