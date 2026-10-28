# Ticket summarizer (remediated)

The same app as `../needs-remediation`, fixed:

- AI usage policy, CODEOWNERS and a pull request template that asks about AI.
- `.ai-provenance.json` declares the generated file with its human reviewer and inventories
  the LLM provider with purpose and owner.
- The API key comes from the environment; `.env` is git-ignored.
- Priority rules are a fixed lookup table instead of evaluated strings; TLS is verified.
- Fixtures use an obviously invalid CPF; dependencies are pinned; tests and CI exist;
  SECURITY.md describes reporting and incident handling.
