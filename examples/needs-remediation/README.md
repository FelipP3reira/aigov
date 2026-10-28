# Ticket summarizer (needs remediation)

A deliberately flawed example for aigov. It is never executed by aigov or its tests.

Intentional problems:

- `app/summarizer.py` is marked as AI-generated but has no human reviewer.
- A demo-only, fake API key is hard-coded.
- `app/fixtures/customers.json` holds a synthetic but check-digit-valid CPF.
- Dynamic evaluation of a rule string and TLS verification turned off.
- The OpenAI SDK is used but no LLM inventory exists.
- No AI usage policy, CODEOWNERS, pull request template, tests, CI or SECURITY.md.
- Dependencies are not pinned.

Compare with `../remediated`.
