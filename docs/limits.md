# Limits of heuristic screening (read before trusting a green matrix)

The selftest matrix is 89/89 against the **shipped corpus and the mock
upstream**. That proves the pipeline does what the policy says for those
inputs. It does not prove the screener catches injections in general.

## What the injection screener cannot do

- **Novel phrasing.** Rules are regexes over weighted phrases. `out-001` in
  the corpus is deliberately a paraphrase ("summarize your guidelines") that
  scores 0.0 inbound; it is only caught because the *output* guard sees the
  canary. Expect real attackers to find more of these. Treat the inbound
  screener as a cheap filter that removes the obvious, and the output guard as
  the control you rely on.
- **Other languages.** Patterns are English. A French "ignore les instructions
  précédentes" scores 0.
- **Semantic attacks.** "Write a poem whose first letters spell the token" has
  no trigger phrase. The canary check still blocks the response if the model
  complies literally, but not if it encodes the token.
- **Encodings beyond base64 / leetspeak / zero-width.** ROT13, hex, Unicode
  homoglyphs and word-splitting with punctuation are not decoded. Adding a
  decoder is a few lines in `injection.py`; adding *every* decoder is not
  possible.
- **Multi-message assembly.** Each message is scored and the maxima combined,
  but an instruction split across many short turns ("remember word A", "now
  word B") is not reconstructed.
- **The optional LLM classifier** inherits the upstream model's own
  injection weaknesses: the text it classifies is wrapped as data, but a
  strong enough payload can still steer it. That is why its weight is blended
  and never replaces the heuristic.

## What the DLP engine cannot do

- Detectors are format-based. A high-entropy string with no recognisable
  prefix (many SaaS tokens) passes. A secret split across two messages
  passes. Base64-encoded secrets pass the DLP stage (they are only decoded by
  the injection screener for *instruction* content).
- `credit_card` relies on Luhn; a Luhn-valid 16-digit order number is a false
  positive (redacted, not blocked, so the user still gets an answer).
- `phone` is North-American; `ssn` is US-only.
- Reversible redaction is a usability feature, not a privacy guarantee: the
  original values stay in memory for the request lifetime and are returned to
  the same authenticated client that sent them.

## What the output guard cannot do

- Prompt-overlap detection uses 8-word n-grams; a model that paraphrases the
  system prompt sentence by sentence without the canary scores below the
  threshold. Lower `prompt_overlap_threshold` at the cost of false positives
  on short quotes.
- HTML sanitisation is regex-based and aimed at the obvious vectors. Clients
  must still render model output as text or through a real HTML sanitiser;
  this layer reduces risk, it does not make raw rendering safe.
- Tool-call filtering checks names, not arguments. An allowed `search_kb`
  called with an injected query is passed through.

## What the mock upstream cannot show

- It never reasons, so "the model refused" paths are untested. Against a real
  model, several `output_leak` cases will return 200 instead of 403 simply
  because the model declines to leak - the corpus expectations encode the
  mock's behaviour, not a universal truth.
- Token usage numbers are character estimates; budget behaviour on a real
  provider depends on its tokenizer.
- Latency, timeouts and partial responses are not simulated.

## What the audit chain cannot do

- It makes tampering **detectable**, not impossible. Someone with write
  access can rewrite the whole file and recompute every hash. Pair it with an
  append-only mount, periodic anchoring of the latest hash somewhere else
  (a ticket, a signed log), and shipping to a SIEM.

## Recommended posture

1. Keep both thresholds and the output guard on; never run inbound-only.
2. Review `injection_warn` records weekly; promote recurring warn-tier
   phrasings to new rules with tests.
3. Add corpus cases for every bypass you find, so the matrix stays honest.
4. Treat the gateway as one layer: least-privilege tools on the application
   side, provider-side safety settings, and human review for consequential
   actions remain necessary.
