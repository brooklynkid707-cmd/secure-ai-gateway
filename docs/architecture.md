# Architecture

The gateway is a single Flask process that mirrors the upstream
`/v1/chat/completions` contract. Clients change one setting (`base_url`) and
everything else - policy, redaction, screening, audit - happens transparently.

## Request pipeline

```mermaid
flowchart TD
    C[Client app / user] -->|POST /v1/chat/completions<br/>Authorization: Bearer key| A

    subgraph GW[Secure AI Gateway]
        A[auth.py<br/>key hash lookup · role · network pin<br/>token bucket · daily budget] -->|identity| P
        P[policy/engine.py<br/>role allow · model allowlist · max_tokens<br/>tools · topics · hours · networks · size] -->|decision| D
        D[dlp.py<br/>PII + secret detectors · Luhn<br/>redact / block / warn · placeholder map] -->|redacted messages| I
        I[injection.py<br/>weighted rules · noisy-OR score<br/>leetspeak / base64 / zero-width<br/>indirect channel multiplier] -->|score < block| S
        I -.->|optional second opinion| L2[llm_client.classify_injection<br/>strict JSON · fallback]
        S[system prompt + canary<br/>client system msgs downgraded] --> U
        U[llm_client.py<br/>urllib POST upstream] --> O
        O[output_guard.py<br/>canary / n-gram leak · secret re-scan<br/>HTML/JS/image sanitise · tool allowlist<br/>placeholder restore] --> R
        R[audit.py<br/>hash-chained JSONL] --> M[metrics.py]
    end

    U -->|chat completion| UP[(Upstream LLM<br/>mock or real)]
    UP --> U
    M -->|200 + X-Gateway-* headers<br/>or 4xx policy error| C

    A -- 401 / 403 / 429 --> R
    P -- 403 / 413 --> R
    D -- 403 dlp_blocked --> R
    I -- 403 injection_blocked --> R
    O -- 403 system_prompt_leak --> R
```

Every exit path writes an audit record; blocks never short-circuit logging.

## Components

| Module | Responsibility | State |
|---|---|---|
| `gateway/server.py` | Flask routes, `Gateway.handle_chat` pipeline | holds all components |
| `gateway/auth.py` | identities (sha256 keys), token bucket, daily budget | in-memory per process |
| `gateway/policy/engine.py` | YAML policy model and ordered evaluation | immutable after load; `clock` override for tests |
| `gateway/dlp.py` | detectors, Luhn, reversible placeholders | per-request `RedactionMap` |
| `gateway/injection.py` | heuristic screener, obfuscation handling, classifier blend | stateless |
| `gateway/output_guard.py` | leak / secret / markup / tool-call controls on the response | stateless |
| `gateway/audit.py` | hash-chained append-only JSONL, `verify()` | file |
| `gateway/metrics.py` | labelled counters, Prometheus text | in-memory |
| `gateway/llm_client.py` | the only outbound HTTP code (urllib) | env-configured |
| `gateway/mock_llm.py` + `scripts/mock_llm_server.py` | deterministic misbehaving upstream | none |
| `gateway/selftest.py` | corpus loader, in-process servers, matrix | none |

## Trust boundaries

1. **Client -> gateway.** Untrusted. Authenticated by API key; everything in the
   body is data. Client `system` messages are honoured only for `admin`.
2. **Gateway -> upstream.** The upstream sees only redacted text plus the
   gateway's own system prompt (with canary). The upstream key lives in an
   environment variable, never in a request from the client.
3. **Upstream -> gateway.** Untrusted. The model may have been manipulated by
   content it processed; its output is re-scanned and sanitised, and its tool
   calls are filtered against the role's allowlist.
4. **Gateway -> audit.** Trusted but tamper-evident. Records carry no raw
   prompts or secret values, so the log cannot become an exfiltration channel.

## Deployment shape

```mermaid
flowchart LR
    subgraph Internal network
        APP1[Chat UI] --> GW
        APP2[Ticket enrichment bot] --> GW
        APP3[Analyst CLI] --> GW
        GW[Secure AI Gateway<br/>:8080] --> AUD[(audit.jsonl)]
        GW --> PROM[Prometheus scrape /metrics]
    end
    GW -->|HTTPS, provider key from env| LLM[(OpenAI-compatible endpoint)]
```

The gateway is stateless apart from quota counters and the audit chain, so
it can run as one container per environment. Multi-instance deployments need
a shared store for rate limits and budgets; see `docs/deployment.md`.
