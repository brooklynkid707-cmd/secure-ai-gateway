# Threat model

Assets: the organisation's data (PII, credentials, source code, customer
records), the gateway's own instructions, the upstream provider key and
spend, and the integrity of the audit trail. Adversaries: a malicious or
careless internal user, an attacker who controls content the model will read
(emails, tickets, web pages, tool output), and a compromised or misbehaving
model.

## OWASP Top 10 for LLM Applications (2025) coverage

| OWASP LLM | Threat in this context | Gateway control | Where | Corpus category |
|---|---|---|---|---|
| LLM01 Prompt Injection | User or document instructs the model to ignore rules, reveal secrets, call tools | Weighted heuristic screener on `user` **and** `tool` content, `<document>` tags screened as indirect, obfuscation folding, optional LLM second opinion, warn/block thresholds; client `system` messages downgraded for non-admins | `injection.py`, `server.py` step 6-7 | `injection`, `indirect_injection` |
| LLM02 Sensitive Information Disclosure | PII / secrets sent upstream; model echoes secrets or its system prompt | Inbound DLP (block / reversible redact / warn), output re-scan, canary and n-gram leak detection | `dlp.py`, `output_guard.py` | `secret_leak`, `pii`, `output_leak` |
| LLM03 Supply Chain | Untrusted upstream model | Single `llm_client.py`, provider key only from env, response shape validated, 502 on any contract break | `llm_client.py` | - |
| LLM04 Data and Model Poisoning | Out of scope for a proxy | - | - | - |
| LLM05 Improper Output Handling | Client renders model HTML/Markdown; script, event handlers, `javascript:` URLs, tracking images | Output sanitiser with image-host allowlist | `output_guard.sanitize_markup` | `output_leak` (out-006/007) |
| LLM06 Excessive Agency | Model calls tools it should not | Request-side tool declaration check per role; response-side `tool_calls` filtered against the same allowlist | `policy/engine.py`, `output_guard.py` | `role_violation` (role-006/007), `output_leak` (out-008/009) |
| LLM07 System Prompt Leakage | Model repeats its instructions or the canary | Per-process canary token in the system prompt; exact match plus 8-gram overlap threshold blocks the response | `output_guard.py` | `output_leak` (out-001/002) |
| LLM08 Vector and Embedding Weaknesses | Out of scope (no RAG inside the gateway); retrieved content arriving as `tool` messages is screened as indirect injection | `injection.py` | `indirect_injection` |
| LLM09 Misinformation | Partially: the gateway cannot verify facts; it surfaces warnings and scores to the client so a human can review | `gateway.warnings` in the response | - |
| LLM10 Unbounded Consumption | Token floods, runaway spend | Token-bucket rate limit, daily token budget per identity, `max_tokens` cap per role, message count and input size caps, 2 MiB body limit | `auth.py`, `policy/engine.py` | `rate_limit`, `role_violation` (role-015/016) |

## MITRE ATLAS mapping

| ATLAS technique | How it would show up here | Control |
|---|---|---|
| AML.T0051 LLM Prompt Injection (direct) | `inj-*` cases | injection screener, block threshold |
| AML.T0051.001 LLM Prompt Injection: Indirect | `ind-*` cases - instructions in tool output, documents, web pages | `tool` role and document tags screened with 1.35x weight |
| AML.T0054 LLM Jailbreak | DAN / developer-mode personas | `developer_mode`, `role_hijack`, `no_restrictions` rules |
| AML.T0056 LLM Meta Prompt Extraction | "repeat your system prompt", paraphrases | inbound `reveal_system_prompt` rule; outbound canary + overlap |
| AML.T0057 LLM Data Leakage | model emits secrets / PII | output re-scan with redact/block |
| AML.T0048 External Harms (Societal / Financial) via Excessive Agency | forbidden tool calls (`delete_records`) | tool allowlist both directions |
| AML.T0043 Craft Adversarial Data (obfuscation) | leetspeak, base64, zero-width | normalisation before rule matching |
| AML.T0024 Exfiltration via ML Inference API | markdown image beacons, "send to URL" instructions | `markdown_exfil`, `exfiltration` rules; external images stripped from output |
| AML.T0029 Denial of ML Service | request floods | token bucket, budgets, size caps |

## MITRE ATT&CK (enterprise) for the surrounding controls

| ATT&CK | Relevance | Control |
|---|---|---|
| T1078 Valid Accounts | stolen / shared API keys | hashed keys, revocation flag, network pinning, per-identity audit |
| T1110 Brute Force | key guessing | 401 on every miss is audited; rate limit applies per identity, body limit per request |
| T1552 Unsecured Credentials | credentials pasted into prompts | DLP block on cloud keys, tokens, private keys |
| T1567 Exfiltration Over Web Service | beacons rendered by the client | image host allowlist, exfil rules |
| T1565.001 Stored Data Manipulation | editing the audit log to hide a block | SHA-256 hash chain, `verify-audit` |
| T1562.001 Impair Defenses | disabling policy | admin-only reload endpoint, audited |

## Residual risks

- Heuristic screening can be bypassed by novel phrasing (see `docs/limits.md`);
  the output guard is the second line and should never be disabled.
- Rate-limit and budget state is per process; a multi-instance deployment
  without a shared store multiplies effective quotas.
- The canary protects the gateway's prompt, not a client-supplied admin
  prompt. Admins who add their own system messages accept that risk.
- Streaming responses are not supported; the gateway serves non-streamed
  so it can inspect the whole output before release.
