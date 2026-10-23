# Deployment notes

## Running

```bash
# offline: bundled mock upstream started in-process
python -m gateway run --policy config/balanced.yaml --upstream mock --port 8080

# real provider: key only ever lives in the environment
export AISEC_LLM_URL="https://api.example-provider.com/v1/chat/completions"
export AISEC_LLM_KEY="<provider key>"
export AISEC_LLM_MODEL="gpt-4o-mini"        # optional: force one upstream model
python -m gateway run --policy config/strict.yaml --upstream "$AISEC_LLM_URL" --port 8080
```

`--upstream` beats `AISEC_LLM_URL`; with neither set the mock is used. The
process prints the policy name, identity count and audit path on start.

## Pointing real applications at it

Any OpenAI-compatible client works by changing the base URL and using a
gateway key instead of the provider key.

**Python (`openai` SDK)**

```python
from openai import OpenAI
client = OpenAI(base_url="http://gateway.internal:8080/v1", api_key="sag-analyst-demo-key-0002")
resp = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "..."}])
print(resp.choices[0].message.content)
```

**curl**

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer sag-analyst-demo-key-0002" \
  -H "Content-Type: application/json" \
  -d '{"model":"mock-gpt","messages":[{"role":"user","content":"Summarize T1110."}]}' -i
```

**Environment-variable based tools** (`OPENAI_BASE_URL`, `OPENAI_API_KEY`):

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=sag-analyst-demo-key-0002
```

Clients receive the usual response JSON plus a `gateway` object and
`X-Gateway-*` headers. Blocks come back as `403/429/413` with an OpenAI-style
`error` object (`error.code` tells you why), so existing error handling keeps
working. Streaming (`stream: true`) is served non-streamed with a warning.

## Hardening checklist

| Item | Why |
|---|---|
| Rotate out the demo keys before anything non-local | they are printed in the README |
| Put TLS in front (reverse proxy or the WSGI server) | bearer keys travel in clear otherwise |
| Run under a production WSGI server (gunicorn/waitress) | Flask's dev server is single-process and unhardened |
| Pass `--trust-proxy` only behind a proxy you control | otherwise `X-Forwarded-For` lets clients spoof network pins |
| Restrict `/metrics` and `/admin/*` at the network layer | admin endpoints need an admin key, metrics are open |
| Ship `audit/*.jsonl` to the SIEM and run `verify-audit` on the archived copy | tamper evidence only helps if someone checks |
| Mount the audit directory append-only (`chattr +a` or object-lock) | the chain detects edits; it cannot prevent them |
| Keep `output.block_on_prompt_leak: true` and `sanitize_html: true` | the output guard is the backstop for everything the inbound screener misses |

## Scaling

- The gateway is stateless except for **rate-limit buckets, daily budgets and
  the audit chain**. Run several instances only if you accept per-instance
  quotas, or replace `Authenticator` buckets/budgets with a shared store
  (Redis `INCR`/`EXPIRE` is enough) and give each instance its own audit file.
- Audit writes are synchronous and lock-serialised; at a few hundred
  requests/second rotate files daily and resume (`AuditLog` continues the chain
  from the last record on start).
- The optional LLM classifier doubles upstream calls for flagged prompts; use
  it with a cheap model and keep `classifier_weight` <= 0.5 so the heuristic
  can still block on its own.

## Operations

| Endpoint | Auth | Use |
|---|---|---|
| `GET /healthz` | none | liveness; `?deep=1` probes the upstream and returns 503 if unreachable |
| `GET /metrics` | none | Prometheus counters: requests by decision/code, policy outcomes, DLP hits, injection outcomes, output findings, tokens per identity |
| `GET /admin/audit?limit=50` | admin | last N audit records |
| `GET /admin/policy` | admin | loaded policy summary and identity list (no key digests) |
| `POST /admin/policy/reload` | admin | re-read both YAML files; audited |

Useful alerts from `/metrics`:

- `gateway_requests_total{code="injection_blocked"}` rising for one identity
  -> probing or a compromised integration.
- `gateway_output_findings_total{finding="canary_token"}` > 0 -> the model is
  leaking under some prompt; capture the request id from the audit log.
- `gateway_requests_total{code="invalid_api_key"}` bursts -> key guessing.
- `gateway_upstream_errors_total` -> provider outage; the gateway fails closed
  (502), it never falls back to an unscreened path.
