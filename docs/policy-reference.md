# Policy reference

A policy is one YAML file (`config/balanced.yaml`, `config/strict.yaml`).
Identities live separately in `config/identities.yaml` so key rotation never
touches the rules.

## Evaluation order

Checks run in this fixed order; the first failure is the response code.

| # | Stage | Code(s) | HTTP |
|---|---|---|---|
| 1 | Bearer key present, known, enabled | `missing_api_key`, `invalid_api_key`, `key_disabled` | 401 |
| 2 | Identity network pin (`identities.yaml: networks`) | `network_denied` | 403 |
| 3 | Token bucket | `rate_limited` | 429 |
| 4 | Body shape | `bad_request` | 400 |
| 5 | Role allowed (`roles.<role>.allow`) | `role_denied` | 403 |
| 6 | Role network list | `network_denied` | 403 |
| 7 | Hours / days | `outside_hours` | 403 |
| 8 | Model allowlist | `model_not_allowed` | 403 |
| 9 | Message count / input size | `too_many_messages`, `input_too_large` | 413 |
| 10 | Declared tools | `tool_not_allowed` | 403 |
| 11 | Denied topics | `topic_denied` | 403 |
| 12 | Daily budget (input estimate) | `budget_exceeded` | 429 |
| 13 | DLP block actions | `dlp_blocked` | 403 |
| 14 | Injection score >= block | `injection_blocked` | 403 |
| 15 | Upstream call | `upstream_error` | 502 |
| 16 | Output guard | `system_prompt_leak`, `output_secret` | 403 |
| - | Allowed | `ok` | 200 |

Warn-tier outcomes (DLP `warn`, injection between thresholds, `max_tokens`
capped, client system prompt downgraded) do not change the status; they are
listed in `X-Gateway-Actions`, `X-Gateway-Warnings` and `gateway.warnings` in
the JSON body, and in the audit record.

## Top-level keys

```yaml
name: balanced
description: free text
system_prompt: |            # prepended to every upstream call; canary appended at runtime
  ...
roles: {...}
topics: {...}
dlp: {...}
injection: {...}
output: {...}
audit: {path: audit/audit.jsonl}
```

## `roles.<name>`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `allow` | bool | `true` | `false` refuses the role outright |
| `models` | list | `[]` (any) | allowed model names; `"*"` allows any |
| `max_tokens` | int | 1024 | cap; larger client values are reduced with a warning |
| `tools` | list | `[]` | function names the role may declare and the model may call |
| `deny_topics` | list | `[]` | topic names (below) the role must not send |
| `hours` | `"HH:MM-HH:MM"` | none | UTC window; may cross midnight (`"22:00-06:00"`) |
| `days` | list | none | `mon`..`sun`; empty = any day |
| `networks` | list | none | CIDRs the role may call from (in addition to the identity pin) |
| `allow_client_system_prompt` | bool | `false` | when false, client `system` messages become `user` messages tagged as data |
| `max_messages` | int | 50 | conversation length cap |
| `max_input_chars` | int | 20000 | total user/tool characters cap |

Roles are fixed to `viewer`, `analyst`, `admin` (ranked in that order in
`auth.ROLES`). A role missing from the policy is denied.

## `topics.<name>`

Organisational data classes, matched with regexes against the concatenated
user/tool text (`re.MULTILINE`; add `(?i)` for case-insensitive patterns).

```yaml
topics:
  source_code:
    description: Proprietary source code
    min_matches: 2          # distinct patterns that must hit
    patterns:
      - '^\s*(def|class)\s+\w+\s*[\(:]'
      - '^\s*(import|from)\s+[\w.]+'
```

`min_matches` is the main false-positive lever: a single `import` word in
prose does not trip `source_code`, a real snippet does.

## `dlp`

```yaml
dlp:
  default_action: redact        # redact | block | warn | ignore
  enabled: [email, phone]       # optional subset; omit for all detectors
  actions:
    private_key: block
    email: redact
    ipv4_private: warn
```

Detector names: `private_key`, `aws_access_key`, `aws_secret_key`,
`github_token`, `slack_token`, `openai_style_key`, `jwt`, `generic_api_key`,
`password_assignment`, `credit_card` (Luhn-validated), `ssn` (area/group/serial
validated), `email`, `phone`, `ipv4_private`.

`redact` replaces the value with `[[DETECTOR_n]]` upstream and restores it in
the response. `block` refuses the request. `warn` leaves the text and records
the finding. A detector set to `warn` or `ignore` inbound keeps that behaviour
on the output path; everything else follows `output.secret_action` /
`output.pii_action`.

## `injection`

```yaml
injection:
  warn_threshold: 0.45
  block_threshold: 0.70
  llm_classifier: false       # second opinion through llm_client (needs AISEC_LLM_URL)
  classifier_weight: 0.5      # blend: (1-w)*heuristic + w*classifier
```

Rule weights are in `injection.RULES`; the score is a noisy-OR of fired
weights, so two 0.5 signals give 0.75. Content in `tool`/`function` messages
and inside `<document>`, `<email>`, `<webpage>`, `<tool_result>`, `<context>`,
`<file>` tags is scored with a 1.35x multiplier.

## `output`

```yaml
output:
  block_on_prompt_leak: true
  prompt_overlap_threshold: 0.30   # fraction of system-prompt 8-grams found in the reply
  secret_action: redact            # redact | block | warn
  pii_action: redact
  sanitize_html: true
  allowed_image_hosts: [example.com]   # subdomains included
```

## Response headers

| Header | Meaning |
|---|---|
| `X-Gateway-Request-Id` | correlates with the audit record |
| `X-Gateway-Decision` | `allow` or `block` |
| `X-Gateway-Code` | `ok` or the block code |
| `X-Gateway-Actions` | comma list, e.g. `dlp_redact,injection_warn,output_sanitized` |
| `X-Gateway-Injection-Score` | final score (0.00-1.00) |
| `X-Gateway-Warnings` | number of warnings in `gateway.warnings` |

## Identities file

```yaml
identities:
  - id: alex-analyst
    role: analyst
    key_sha256: <hex>           # python -m gateway hash-key
    requests_per_minute: 120
    burst: 40
    daily_token_budget: 200000
    networks: [10.0.0.0/8]      # optional
    disabled: false
```

Reload both files without restarting: `POST /admin/policy/reload` with an
admin key. Quota counters survive the reload.
