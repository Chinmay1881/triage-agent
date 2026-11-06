# Phase 3b four-agent chain vs single-agent baseline

Scenarios s01 and s08, seed 42, variant 1.

**Read these numbers with three caveats:**

- **Different models.** The baseline ran on `gpt-oss-120b`. This smoke test ran every agent on `gpt-oss-20b`, a smaller model. The `gpt-oss-120b` acceptance runs are still to come, so this isn't a like-for-like comparison.
- **Fixes after the run.** Two reviewer defects found in this smoke test were fixed afterwards (see "Fixed after this run"). A rerun with the fixes hit `gpt-oss-20b`'s daily limit (198,240 of 200,000 tokens) and produced no usable result, so the fixes are checked by mock tests only.
- **One run each.** Model output varies between runs, so small differences mean little.

Sources: `phase3_single_agent_baseline.json` (code at `fb8e798`) and `phase3b_smoke_20b.json`.

## Summary

| | s01 baseline | s01 chain | s08 baseline | s08 chain |
| --- | --- | --- | --- | --- |
| Model | 120b | 20b | 120b | 20b |
| Findings produced | **0** | 11 | 15 | 6 |
| Findings reportable | not applicable | 6 | not applicable | 4 |
| LLM-chosen tool calls | 12 of 12 | 9 (investigator 7 of 10, reviewer 2) | 12 of 12 | 8 (investigator 5 of 8, reviewer 3) |
| Tool errors | 0 | 0 | 3 | 0 |
| LLM calls | 17, plus 4 rejected | 21, including 1 rejected | 18 | 16 |
| Tokens counted against limits | 59,065, not counting the rejected calls | 73,213 | 57,887 | 51,675 |
| Of those, investigator + reviewer | 59,065 | 68,633 | 57,887 | 46,905 |
| Duration | 520 s | 498 s | 438 s | 389 s |

**The chain produced findings for s01 where the baseline produced none, and caught unverified claims, but it missed the token target.** The 45,000-token target counts tokens against `gpt-oss-120b`'s limit, which the investigator and reviewer would use in the default setup. They used 68,633 on s01 (which had a reopen) and 46,905 on s08, measured here on `gpt-oss-20b`.

## Acceptance checks (on `gpt-oss-20b`, before the fixes)

| Check | Result | Evidence |
| --- | --- | --- |
| s01's findings include the payload starting, with grounded citations | Pass | F3, confirmed: `msupdate.exe` launched by `powershell.exe`, unsigned, known-bad hash `[evt_004052, tool:check_reputation#6]` |
| s01's findings include its beacons, with grounded citations | Pass, incomplete | F5, confirmed: `[evt_004054, evt_004087]`. It says "twice", but the data has 3; the third (`evt_004127`, 10:06:50) falls outside the 09:50–10:05 window searched |
| s08's intel brief shows the parent AdminToolkit hash as known_good | Pass | `process_chain` parent: `AdminToolkit.exe`, `known_good`, from `tool:check_reputation#4` |
| No unverified absence claims survive review | Pass | All 3 of s01's and 2 of s08's unverified absence claims were disputed. s08's F4 was confirmed after the reviewer's own `get_network_connections` calls |

## What each agent contributed

| Agent | s01 | s08 |
| --- | --- | --- |
| Sentinel-Triage | P2, endpoint; budget 10. 925 tokens | P3, endpoint; budget 8. 983 tokens |
| CyberIntel-Agent | 8 code lookups. Found the `msupdate.exe` child and marked it known_bad before any investigation. Its one LLM lookup was rejected by the API (malformed JSON), and the brief was unaffected. 3,655 tokens | 6 code lookups. AdminToolkit known_good and signed by Northbeam, in the brief every time. 3,787 tokens |
| Investigator-Agent | 7 calls, 6 automatic reputation lookups, 11 findings. 46,579 tokens | 5 calls, 2 automatic reputation lookups, 6 findings. 34,004 tokens |
| Reviewer-Agent | 2 calls, one reopen. Confirmed 6, disputed 5. 22,054 tokens | 3 calls, 2 automatic reputation lookups. Confirmed 4, disputed 2. 12,901 tokens |

Grounding dropped 2 findings and removed 2 citations on s08, and none on s01.

## Findings

### s01, single-agent baseline

None. Groq rejected all 4 `summarize_findings` attempts (HTTP 400).

### s01, chain

| ID | Status | Finding | Citations |
| --- | --- | --- | --- |
| F1 | Disputed (wrongly) | WINWORD.EXE spawned powershell.exe with an encoded command that downloads from `invoice-portal.example` | `evt_004047` |
| F2 | Disputed (wrongly) | The decoded command downloads to `msupdate.exe` and runs it | `evt_004047` |
| F3 | Confirmed | `msupdate.exe` launched by powershell.exe, unsigned, known-bad hash | `evt_004052`, `tool:check_reputation#6` |
| F4 | Confirmed | powershell.exe connected to 203.0.113.116 on port 80 | `evt_004049`, `tool:get_network_connections#15` |
| F5 | Confirmed | `msupdate.exe` connected to 203.0.113.116 on port 443 "twice" (3 in the data) | `evt_004054`, `evt_004087`, `tool:get_network_connections#15` |
| F6 | Disputed (see fix 2) | No persistence events | `tool:get_persistence_events#17` |
| F7 | Disputed (see fix 2) | No logon events for ben.r in the window | `tool:get_logon_history#14` |
| F8 | Disputed | No other processes ran the same command | `tool:search_process_events#18` |
| F9 | Confirmed | DNS query for `go.xero.com` (routine, not security-relevant) | `tool:get_dns_queries#10` |
| F10 | Confirmed | `OneDrive.exe` connection (routine, not security-relevant) | `tool:get_network_connections#15` |
| F11 | Confirmed (**false**) | The file was created by `msupdate.exe`. `evt_004050` shows `powershell.exe` wrote it | a `get_process_tree` ref |

### s08, single-agent baseline

15 findings (2 withheld by the classifier), including one unverified absence claim. They're listed in `phase3_single_agent_baseline.json`. One of them is "No additional AdminToolkit.exe instances were observed".

### s08, chain

| ID | Status | Finding | Citations |
| --- | --- | --- | --- |
| F1 | Confirmed | powershell.exe started by AdminToolkit.exe; the encoded command is a temp cleanup and DNS cache clear | `evt_008227` |
| F2 | Confirmed | AdminToolkit.exe launched by explorer.exe as a scheduled maintenance task | `evt_008225` |
| F3 | Confirmed | The script wrote to `C:\ProgramData\Northbeam\maint.log` | `evt_008229` |
| F4 | Confirmed | No outbound connections from PowerShell, 13:20–13:30 | `tool:get_network_connections#11` |
| F5 | Disputed (see fix 2) | No persistence created by PowerShell | `tool:get_persistence_events#12` |
| F6 | Disputed | No additional logons for felix.w | `tool:get_logon_history#13` |

## Tool calls in order

Code-run lookups aren't listed. `+n` means n automatic reputation lookups (`intel_rule`) that cost no budget.

**s01 baseline:** `search_process_events`, `get_network_connections`, `check_reputation`, `get_process_tree`, `get_persistence_events`, `check_reputation`, `score_anomaly`, `lookup_attack_technique`, `lookup_attack_technique`, `check_reputation`, `get_dns_queries`, `get_process_tree`

**s01 chain:**
- Investigator: `get_dns_queries` +3, `get_logon_history`, `get_network_connections` +1, `get_persistence_events`, `search_process_events`, then after the reopen `get_process_tree` +2, `score_anomaly`
- Reviewer: `get_persistence_events`, `get_logon_history`

**s08 baseline:** `search_process_events` (error), `search_process_events`, `get_process_tree`, `check_reputation`, `check_reputation`, `get_process_tree`, `get_logon_history` (error), `get_logon_history` (error), `get_logon_history`, `get_process_tree`, `search_attack_techniques`, `get_network_connections`

**s08 chain:**
- Investigator: `get_process_tree` +2, `get_network_connections`, `get_persistence_events`, `get_logon_history`, `score_anomaly`
- Reviewer: `get_network_connections`, `get_persistence_events`, `get_network_connections` +2

## Tool errors, and why

The smoke runs had no tool errors. The one failure was at the API: CyberIntel-Agent's `gpt-oss-20b` produced malformed tool-call JSON on s01, which Groq rejected.

All three errors were in the s08 baseline, and all three were time windows over 24 hours:

| Call | Window the model asked for | Error | Why |
| --- | --- | --- | --- |
| `search_process_events` | 25 h | "time window is 25 h; the maximum is 24 h" | Clear; the model simply asked for too much |
| `get_logon_history` | 48 h | "time window is 48 h; the maximum is 24 h" | Clear; the same mistake |
| `get_logon_history` | 24 h 5 min | "time window is 24 h; the maximum is 24 h" | **A usability bug:** the message rounds, so it reads as nonsense |

Suggested fixes (not made yet):
1. Print the actual duration in the error, such as "24.1 h".
2. Tell the model which window was used when `start`, `end` and `around` are all given. The models send all three on many calls; `around` is silently ignored, and the code accepts this.

## Tokens

| | Tool schemas per call | First and last `investigate` input, s01 | First and last `investigate` input, s08 |
| --- | --- | --- | --- |
| Before | about 1,844 tokens (12 tools) | not compared | not compared |
| Chain | about 1,289 tokens (7 tools) | 3,355 and 5,946 | 3,066 and 4,295 |

Why the target was missed:
- **The reviewer costs more than estimated:** 22,054 tokens on s01 against an estimate of about 12,000, mostly reasoning output at `medium` effort.
- **The reopen on s01** added investigator and reviewer calls.
- **Repeated lookups:** the investigator re-ran `get_process_tree` and `score_anomaly` calls that CyberIntel-Agent had already made, despite the prompt.
- **The intel facts** in every `investigate` call offset some of the schema savings.

Ideas for the next pass, none tested yet:
- Answer an exact repeat of an earlier call from the ledger, at no cost.
- Run the reviewer at `low` effort.
- Skip the reviewer's tool turn when no absence claims are pending.

## Fixed after this run (mock tests only)

1. **False disputes of true findings (s01 F1, F2).** The verdict prompt didn't include the trigger event or intel facts, so the reviewer really had no evidence for them. It now gets the trigger events, the cited events and the intel facts, which adds tokens to every verdict.
2. **Verified absences marked unverified (s01 F6 and F7, s08 F5).** The reviewer re-ran those tools, but code only accepted a ref the model quoted correctly. Code now also accepts a successful reviewer call to the same tool the claim cites, read from the tool log.

## Still open

- **Grounding can't check attribution.** F11 names real entities and cites a real tool result, so it passes, though its claim about who wrote the file is false. The reviewer confirmed it, which suggests tool-ref citations are weaker than event citations.
- **`summarize_findings` still keeps trivia on `gpt-oss-20b`** (F9, F10), despite the prompt.
- **`first_checks` nudge:** it fired on s08 and on both baseline runs, pushing up tool use.
- **A failed `plan` call ends the run with an error.** That's how the rerun's s08 ended when the daily limit hit; every other agent degrades instead.
