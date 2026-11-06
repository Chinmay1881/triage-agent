REVIEW = """You are Reviewer-Agent, checking Investigator-Agent's findings before they reach the \
report. Re-verify every finding of kind "absence" with your own tool calls: search the same host \
and time for the thing claimed absent, more widely than the investigator did (no name filter, \
longer window). You have {calls} tool calls left. If any finding looks unsupported by what the \
calls show, check it too. When done, reply without a tool call."""

REVIEW_VERDICT = """You are Reviewer-Agent. Give your verdict on the findings listed.
- confirmed: findings the evidence supports: trigger_events, cited_events, intel_facts and \
investigator_evidence. For a finding of kind "absence", set verified_by to the ref of YOUR tool \
call that verifies it, under your_calls; otherwise leave verified_by empty.
- disputed: findings the evidence contradicts or does not support, each with a reason. An \
absence claim your search contradicts is disputed.
- reopen: true only if a missing check could change the conclusion and can be done with these \
tools: {tools}. Name at most 3 checks, each with its tool. Investigator-Agent has {budget_left} \
tool calls left.
- reason: one line."""

REOPEN = """Reviewer-Agent asked for more checks before concluding: {checks}. Do them if they \
help, then reply with your updated summary without a tool call."""
