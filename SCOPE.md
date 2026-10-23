# Scope, authorization and responsible use

The Secure AI Gateway is a **defensive** control: it sits between your own
users and an LLM endpoint you are entitled to use, and it enforces your own
organisation's rules. Nothing in this repository attacks third-party systems.
The attack corpus exists to test *this gateway*, on *your* deployment.

## What the attack corpus is - and is not

- Every case in `tests/attack_corpus/` targets a benign, measurable outcome:
  make the model print `PWNED`, echo the gateway's canary token, invent a
  documentation-example cloud key, emit a `<script>` tag, or call a tool the
  role is not allowed to use. None of the prompts request harmful real-world
  content, and the mock upstream cannot produce any.
- The corpus is replayed only against the gateway you start (in-process on a
  loopback port, or a URL you pass with `--url`). Do not point `selftest` or
  `replay` at a gateway or model endpoint you do not operate or have written
  permission to test.
- Secrets in the corpus and samples are synthetic: Amazon's published
  documentation example key, padded `ghp_xxx...` strings, invalid-area SSNs,
  test card numbers and `example.com` addresses. Do not replace them with real
  credentials "to see if it works" - the DLP tests already prove it does, and
  the audit log would then hold masked fragments of real secrets.

## Running against a real model

When you set `AISEC_LLM_URL` (or `--upstream`) to a real provider:

1. Use a key scoped to a test project with a spending cap.
2. Keep the `strict` policy during evaluation; loosen deliberately.
3. Expect the model to behave differently from the mock. The selftest cases in
   `output_leak` rely on the mock *choosing* to leak; a real model may refuse,
   which shows up as a 200 where the corpus expected a 403. That is a corpus
   expectation written for the mock, not a gateway bug - see
   `docs/limits.md`.
4. Review the provider's terms before sending adversarial prompts; most allow
   red-teaming of your own integration but not attempts to extract their
   system prompts or weights.

## Rules of engagement checklist

- [ ] The upstream endpoint is mine or I have written permission to test it.
- [ ] Identities in `config/identities.yaml` are mine; demo keys are rotated
      out before any non-local deployment.
- [ ] The audit log location is access-controlled and backed up; it is the
      evidence trail for every block decision.
- [ ] Nobody is relying on the heuristic injection screener as the *only*
      control (see `docs/limits.md`).
