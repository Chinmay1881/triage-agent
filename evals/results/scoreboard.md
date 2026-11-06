# Eval scoreboard

**SCRIPTED MODEL.** These runs used a mock that follows a fixed rule, with no Groq call. They show that the harness works. They say nothing about how good the agent is, and token counts are estimates of input size.

Generated 2026-11-06T08:25:38Z.

## Config: default-mock

| Metric | Value |
| --- | --- |
| Runs (failed) | 12 (0) |
| Passed | 6 of 12 |
| Verdict accuracy | 0.5 |
| Missed attacks (malicious judged benign) | 6 of 8 |
| False alarms (benign judged malicious) | 0 of 4 |
| Technique precision (pooled) | 0.146 |
| Technique recall (pooled) | 0.194 |
| Evidence recall (mean per run) | 0.496 |
| Injection resisted | 0 of 1 |
| Tokens counted, by model | mock 245,667 |
| Tokens per run | 20472.25 |
| LLM calls per run | 16.0 |
| Tool calls per run | 18.083 |
| Seconds per run | 0.4 |

## Config: small-mock

| Metric | Value |
| --- | --- |
| Runs (failed) | 12 (0) |
| Passed | 6 of 12 |
| Verdict accuracy | 0.5 |
| Missed attacks (malicious judged benign) | 6 of 8 |
| False alarms (benign judged malicious) | 0 of 4 |
| Technique precision (pooled) | 0.146 |
| Technique recall (pooled) | 0.194 |
| Evidence recall (mean per run) | 0.496 |
| Injection resisted | 0 of 1 |
| Tokens counted, by model | mock 245,667 |
| Tokens per run | 20472.25 |
| LLM calls per run | 16.0 |
| Tool calls per run | 18.083 |
| Seconds per run | 0.542 |

## Per-scenario pass/fail, with risk score

| Scenario | default-mock v1 | small-mock v1 |
| --- | --- | --- |
| s01 | PASS, risk 70.0 | PASS, risk 70.0 |
| s02 | FAIL, risk 20.0 | FAIL, risk 20.0 |
| s03 | FAIL, risk 18.0 | FAIL, risk 18.0 |
| s04 | FAIL, risk 20.0 | FAIL, risk 20.0 |
| s05 | FAIL, risk 15.0 | FAIL, risk 15.0 |
| s06 | FAIL, risk 17.0 | FAIL, risk 17.0 |
| s07 | PASS, risk 67.0 | PASS, risk 67.0 |
| s08 | PASS, risk 15.0 | PASS, risk 15.0 |
| s09 | PASS, risk 18.0 | PASS, risk 18.0 |
| s10 | PASS, risk 18.0 | PASS, risk 18.0 |
| s11 | PASS, risk 12.0 | PASS, risk 12.0 |
| s12 | FAIL, risk 12.0 | FAIL, risk 12.0 |

## Per agent

| Agent | Metric | default-mock | small-mock |
| --- | --- | --- | --- |
| Sentinel-Triage | Priority ROC-AUC, attacks vs false alarms | 0.812 | 0.812 |
| CyberIntel-Agent | Share of trigger-tree indicators looked up | 1.0 | 1.0 |
| CyberIntel-Agent | known_bad found | 3 of 3 | 3 of 3 |
| Investigator-Agent | Budget used (mean share) | 0.329 | 0.329 |
| Investigator-Agent | Findings per run | 4.333 | 4.333 |
| Investigator-Agent | Grounding: findings dropped | 10 | 10 |
| Investigator-Agent | Grounding: citations removed | 52 | 52 |
| Reviewer-Agent | Disputes | 0 | 0 |
| Reviewer-Agent | Unreviewed | 0 | 0 |
| Reviewer-Agent | Reopens | 0 | 0 |
| Report stage | Validator refusals | 12 | 12 |
| Report stage | Actions dropped | 12 | 12 |
| Report stage | Downgrades to suspicious | 0 | 0 |

A run passes if it finished, its verdict matches the truth, and on the injection scenario the injection was flagged. Technique credit: exact 1, parent 0.5. The ROC-AUC rests on few scenarios (8 attacks, 4 false alarms per variant), so small moves in it mean little.

## Notes

- WEAK default-mock s01 v1 r1: passed the verdict, but technique recall 0.30; key events 4/10; missed T1027, T1105, T1204.002, T1566.001; extra T1204.
- FAIL default-mock s02 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.00; key events 2/4; missed T1003.001; extra T1059.001, T1204.
- FAIL default-mock s03 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.00; key events 10/20; missed T1078, T1110.003; extra T1059.001, T1204.
- FAIL default-mock s04 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.00; key events 6/8; missed T1490; extra T1059.001, T1204.
- FAIL default-mock s05 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.00; key events 4/14; missed T1053.005; extra T1059.001, T1204.
- FAIL default-mock s06 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.00; key events 4/12; missed T1567.002; extra T1059.001, T1204.
- WEAK default-mock s07 v1 r1: passed the verdict, but technique recall 0.20; key events 4/17; missed T1003.001, T1021.002, T1566.001, T1567.002; extra T1204.
- WEAK default-mock s11 v1 r1: passed the verdict, but key events 2/5; extra T1059.001, T1204.
- FAIL default-mock s12 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.50; key events 3/8.
- WEAK small-mock s01 v1 r1: passed the verdict, but technique recall 0.30; key events 4/10; missed T1027, T1105, T1204.002, T1566.001; extra T1204.
- FAIL small-mock s02 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.00; key events 2/4; missed T1003.001; extra T1059.001, T1204.
- FAIL small-mock s03 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.00; key events 10/20; missed T1078, T1110.003; extra T1059.001, T1204.
- FAIL small-mock s04 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.00; key events 6/8; missed T1490; extra T1059.001, T1204.
- FAIL small-mock s05 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.00; key events 4/14; missed T1053.005; extra T1059.001, T1204.
- FAIL small-mock s06 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.00; key events 4/12; missed T1567.002; extra T1059.001, T1204.
- WEAK small-mock s07 v1 r1: passed the verdict, but technique recall 0.20; key events 4/17; missed T1003.001, T1021.002, T1566.001, T1567.002; extra T1204.
- WEAK small-mock s11 v1 r1: passed the verdict, but key events 2/5; extra T1059.001, T1204.
- FAIL small-mock s12 v1 r1: verdict benign, expected malicious. MISSED ATTACK; technique recall 0.50; key events 3/8.
