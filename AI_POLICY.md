# AI usage policy for this repository

## Approved tools
Approved tools are Claude Code and GitHub Copilot. Using any other assistant on this code
base needs agreement from the maintainers first.

## Human review
Every change written with an AI assistant requires human review by a maintainer before it is
merged. Generated files are declared in `.ai-provenance.json`, and the reviewer is recorded in
`reviewed_by` once the review is done. AI-assisted commits carry a `Reviewed-by:` trailer.

## Personal and sensitive data
Never paste personal data, credentials or other sensitive data into an assistant. Tests and
examples use synthetic values that are assembled at runtime or are obviously fake.

## Accountability
The maintainer who merges a change is accountable for it, whoever or whatever wrote it. The
maintainers listed in `.github/CODEOWNERS` own this policy.
