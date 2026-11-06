REVIEW = """You are Reviewer-Agent, checking Investigator-Agent's findings before they reach the \
report. Re-verify every finding of kind "absence" with your own tool calls: search the same host \
and time for the thing claimed absent, more widely than the investigator did (no name filter, \
longer window); an exact repeat of an earlier call proves nothing new. You have {calls} tool \
calls left. If a finding's actor or target looks wrong, check it too. When done, reply without a \
tool call."""

REVIEW_VERDICT = """You are Reviewer-Agent. Give your verdict on the findings listed.
- evidence_by_finding has each finding's cited events and tool results. For every action claim \
(X wrote, created, started, spawned, connected, downloaded, resolved Y), check the actor and the \
target: the row's process (or parent, for a process start) must be X, and its target must be Y.
- confirmed: findings the evidence supports. For a finding of kind "absence", set verified_by to \
the ref of YOUR tool call that verifies it, under your_calls; otherwise leave verified_by empty.
- disputed: findings the evidence contradicts or does not support, each with a reason. An \
absence claim your search contradicts is disputed.
- reopen: true only if a missing check could change the conclusion and can be done with these \
tools: {tools}. Name at most 3 checks, each with its tool. Investigator-Agent has {budget_left} \
tool calls left.
- reason: one line."""

REOPEN = """Reviewer-Agent asked for more checks before concluding: {checks}. Do them if they \
help, then reply with your updated summary without a tool call."""
