# aigov

A heuristic governance scorecard for code written with generative AI assistants.

`aigov` reads a repository and checks whether AI-assisted code goes through basic governance
controls: a usage policy, declared provenance, human review, secret and personal-data hygiene,
tests and CI. It writes a self-contained HTML report and a JSON file that engineering teams can
keep as evidence and track over time.

> **aigov is a heuristic scorecard. It is not legal advice, not an audit and not a
> certification, and it does not attest compliance with any law, regulation or standard.**
> The four NIST AI RMF functions (Govern, Map, Measure, Manage) are used only to organise the
> report.

Python 3.9+, standard library only, zero runtime dependencies.

## What it is, and what it is not

| aigov is | aigov is not |
| --- | --- |
| A fast, read-only check you can run locally and in CI | A detector of AI authorship |
| A way to make AI use *declared* and *reviewed* | Proof that AI was or was not used |
| 13 transparent, documented heuristics with weights | A legal opinion or a compliance certificate |
| A gate that fails builds below a score or on critical findings | A replacement for code review, SAST or secret scanning services |

## Quickstart

```bash
git clone https://github.com/FelipP3reira/aigov.git && cd aigov
python -m aigov scan /path/to/repo                    # writes ./aigov-report.html
python -m aigov scan /path/to/repo --json report.json # also writes JSON
pip install .  &&  aigov scan /path/to/repo           # optional: install the command
```

```
python -m aigov scan [PATH] [--policy FILE] [--html FILE] [--no-html]
                     [--json FILE] [--fail-under N] [--quiet]
```

| Option | Meaning |
| --- | --- |
| `PATH` | Repository to scan (default: current directory). |
| `--policy FILE` | Policy file. Default: `PATH/aigov.policy.json` if present, else built-in defaults. |
| `--html FILE` | HTML report path. Default: `./aigov-report.html` in the *current* directory, never inside the scanned repository. |
| `--no-html` | Do not write HTML. |
| `--json FILE` | Also write the JSON report. |
| `--fail-under N` | Minimum score for the gate (overrides `min_score`). |
| `--quiet` | Print only the final line: `Score 88/100 \| Aligned \| gate passed`. |

Exit codes: `0` gate passed, `1` gate failed (score below the minimum, or a critical finding
while `block_on_critical` is on), `2` usage error (bad arguments, missing path, invalid policy).

### Demo

`python scripts/build_demo.py` copies the two examples to a temporary directory, gives each a
small git history (an AI co-authored commit without `Reviewed-by` in one, with it in the
other), scans them and writes `docs/demo/needs-remediation.html`, `docs/demo/remediated.html`,
their JSON, and `docs/demo/index.html` with both reports side by side.

| Example | Score | Verdict |
| --- | --- | --- |
| `examples/needs-remediation` | 6.9 | Blocked (hard-coded key) |
| `examples/remediated` | 100 | Aligned |

## Provenance signals

aigov does **not** detect whether code was written by AI. It reads what the team declares,
from three sources. **The absence of signals does not prove that AI was not used.**

### 1. `.ai-provenance.json` at the repository root

```json
{
  "ai_systems": [
    {"provider": "anthropic", "purpose": "Summarise tickets", "owner": "support-platform",
     "data_categories": ["ticket text"]}
  ],
  "files": [
    {"path": "src/x.py", "tool": "claude", "model": "claude-sonnet",
     "reviewed_by": "Ana Souza", "reviewed_at": "2026-10-01"}
  ]
}
```

- `ai_systems` is the inventory of LLM providers **the product calls** (used by MAP-02).
  `provider` is required; `purpose` and `owner` are expected.
- `files` declares AI-generated files (used by MAP-01 and MEA-02). `path` and `tool` are
  required; `reviewed_at` must be `YYYY-MM-DD`.
- Invalid entries are dropped and reported as MAP-01 findings. Absolute paths and paths with
  `..` are rejected.

### 2. Header markers (first 40 lines of code files)

```python
# @ai-generated: claude          (or  @ai-assisted: copilot)
# @model: claude-sonnet
# @reviewed-by: Ana Souza
# @reviewed-at: 2026-10-01
```

Any common comment leader works (`#`, `//`, `/*`, `*`, `<!--`, `--`); trailing `*/` and `-->`
are stripped. When a file appears both in the manifest and with markers, manifest values win
and empty fields are filled from the markers.

### 3. Git history

A commit is AI-assisted when it has any of:

- `Co-authored-by:` naming an AI actor (claude, copilot, cursor, codex, openai, chatgpt,
  gemini, devin, aider, ...);
- a `Generated with <tool>` footer where the tool is an AI actor;
- an `AI-Assisted:` or `Assisted-by:` trailer with an affirmative value (anything except
  `no`, `false`, `0`, `none`, `n/a`, ...);
- an author that is an AI actor;
- a match for one of the policy's `extra_ai_commit_patterns`.

Review evidence is a `Reviewed-by:` trailer naming a human. A reviewer that is an AI actor
does not count. E-mail addresses are never stored or reported, only names.

## Controls

Status is derived from findings: any high or critical finding fails the control, low or
medium warns, none (or info only) passes. N/A controls are excluded from the score.

| ID | Function | Weight | Passes when | Warns | Fails |
| --- | --- | --- | --- | --- | --- |
| GOV-01 | Govern | 3 | An AI policy (`AI_POLICY.md`, `docs/ai-usage.md`, ...) covers human review, personal/sensitive data, approved tools and accountability | A topic is missing | No policy file |
| GOV-02 | Govern | 2 | `CODEOWNERS` has at least one rule with an `@owner` or e-mail | | Missing, or no valid rule |
| GOV-03 | Govern | 2 | A PR template mentions AI and human review | One of the two is missing | No PR template |
| MAP-01 | Map | 3 | Every declared AI file exists and has a human reviewer | No signals at all; manifest errors; declared file missing | Declared file without a human reviewer (an AI reviewer does not count); AI signals while policy says `ai_usage: "none"` |
| MAP-02 | Map | 2 | Every LLM provider found in imports or dependency manifests is in `ai_systems` | Inventory entry without purpose or owner | Provider used but not inventoried |
| MAP-03 | Map | 3 | No valid CPF (check digits) or payment card (Luhn + plausible prefix) | Found in test/fixture paths | Found elsewhere |
| MEA-01 | Measure | 3 | No secrets | | Known-format secret (critical: AWS, GitHub, Anthropic, OpenAI-style, Google, Slack, Stripe live, private key block); generic `password/token/api_key = "..."` with entropy >= 3.0 (high, medium in tests); env file not covered by `.gitignore` (high) |
| MEA-02 | Measure | 2 | No risky patterns outside tests and comments | Pattern in an undeclared file | Pattern in a file declared as AI-generated |
| MEA-03 | Measure | 2 | Test files / source files >= `min_test_ratio` | Ratio below minimum | No tests at all |
| MAN-01 | Manage | 3 | Share of AI-assisted commits with a human `Reviewed-by` >= `review_threshold` | >= half the threshold | Below half. N/A without git or without AI-assisted commits |
| MAN-02 | Manage | 2 | CI config (GitHub Actions, GitLab, Jenkins, Azure, CircleCI, Bitbucket) runs tests | CI without a recognised test step | No CI |
| MAN-03 | Manage | 1 | Lockfiles next to `package.json`, `composer.json`, `Pipfile`, `go.mod`, `Cargo.toml`, `Gemfile`; `==` in `requirements*.txt`; `pyproject.toml` dependencies locked (poetry/uv/pdm) or pinned | Unpinned requirement | Manifest without lockfile. N/A when no dependencies are declared |
| MAN-04 | Manage | 1 | `SECURITY.md` | Only an incident runbook | Neither |

MEA-02 patterns: `eval`/`exec`/`new Function`, `shell=True`, `os.system`/`os.popen`, `pickle`,
`yaml.load` without `SafeLoader`, `child_process` exec, `innerHTML`/`document.write`, PHP
command functions and `unserialize`, disabled TLS verification (`verify=False`,
`rejectUnauthorized: false`, `InsecureSkipVerify`, ...) and SQL built by concatenation or
formatting.

### Score and verdict

```
score = sum(weight x points) / sum(weights of assessed controls) x 100
points: pass = 1, warn = 0.5, fail = 0; N/A is excluded
```

A score is also computed per function. Verdict: **Blocked** if there is any critical finding,
otherwise **Aligned** (>= 85), **Partial** (>= 60) or **Gaps**.

## Policy: `aigov.policy.json`

Unknown keys are an error, so typos cannot silently weaken the gate.

| Key | Default | Meaning |
| --- | --- | --- |
| `ai_usage` | `"declared"` | `"none"` makes any AI signal a MAP-01 failure. |
| `min_score` | `70` | Gate threshold (0-100). |
| `block_on_critical` | `true` | Fail the gate on any critical finding. |
| `review_threshold` | `0.8` | Required share of AI-assisted commits with human review. |
| `min_test_ratio` | `0.1` | Test files per source file. |
| `max_file_bytes` | `1000000` | Larger files are skipped. |
| `ignore` | `[]` | Globs on repository-relative paths, e.g. `"examples/*"`. `*` also matches `/`. |
| `disabled_controls` | `[]` | Control IDs reported as N/A with "Disabled by policy". |
| `extra_ai_commit_patterns` | `[]` | Case-insensitive regexes marking a commit as AI-assisted; validated at load time. |

## Suppressions

- `# aigov:ignore` on a line suppresses findings on that line.
- `aigov:ignore-file` within the first 40 lines suppresses findings in the whole file.

Suppressions are transparent: every suppressed finding is listed in the HTML report, the JSON
(`suppressions`) and counted on the console, with file, line, scope, control and the line of
the directive. Findings that are not tied to a file (e.g. "No CI configuration") cannot be
suppressed; use `disabled_controls`, which is also visible in the report.

## Using it in CI

```yaml
# .github/workflows/aigov.yml
name: aigov
on: [pull_request]
permissions:
  contents: read
jobs:
  scorecard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0              # full history for MAN-01
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "git+https://github.com/FelipP3reira/aigov@v0.1.0"
      - run: aigov scan . --html aigov-report.html --json aigov-report.json
      - uses: actions/upload-artifact@v4
        if: always()                  # publish the report even when the gate fails
        with:
          name: aigov-report
          path: |
            aigov-report.html
            aigov-report.json
```

This repository runs its own tests on Python 3.9 to 3.13 and scans itself in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Limitations

- **No authorship detection.** aigov reads declarations. Undeclared AI use is invisible to it.
- **Heuristics.** Checks are based on file names and regular expressions. Expect false
  positives (e.g. a person named "Claude" is treated as an AI actor) and false negatives
  (secrets in unsupported formats, obfuscated risky calls).
- Secrets and personal data: a fixed set of formats only (CPF, payment cards, listed API key
  prefixes, generic assignments). Other national IDs, e-mails or phone numbers are not checked.
- Provider detection reads Python, JavaScript/TypeScript and Go imports plus dependency
  manifests. Other languages are only covered through their manifests. Test files are not
  used for provider detection.
- Comment detection is line-based; docstrings and multi-line strings are scanned as code.
- Commit trailers are read anywhere in the commit body, not only in the last paragraph.
- `.gitignore` support is a subset (root and nested files, globs, negation, directory rules).
  When in doubt an env file is treated as *not* ignored, so it is reported.
- Limits: files over `max_file_bytes`, binary files and symlinks are skipped (listed in the
  report); at most 50 000 files and 5 000 commits are read.
- Keyword checks (AI policy topics, PR template) confirm that topics are mentioned, not that
  the text is adequate.

## Threat model and security design

aigov is meant to be safe to run on untrusted repositories.

- **Read-only.** It never imports, executes or writes to the scanned repository. Reports go to
  the paths you pass, defaulting to the current directory.
- **No symlinks or junctions** are followed. `.git`, `node_modules`, `vendor`, `venv`/`.venv`,
  `dist`, `build`, `__pycache__` and similar directories are skipped.
- **Git hardening.** `git` is the only process started, with a 30 s timeout,
  `GIT_TERMINAL_PROMPT=0`, `-c core.fsmonitor=false`, no pager, `log.showSignature=false` (so a
  repository-configured gpg program cannot run), `--no-textconv` and `--no-ext-diff`.
- **Masking.** Secrets and personal data never appear in clear text: `sk-p… (48 characters,
  masked)`, `***.***.***-09`, `**** **** **** 1111 (16 digits, masked)`. Tests assert that raw
  values are absent from console, JSON and HTML.
- **HTML safety.** Every repository-derived string is escaped with `html.escape`. The report is
  a single file with no external resources, and a Content-Security-Policy pins the inline CSS
  and JS by SHA-256 hash, so an escaping mistake still cannot run injected script.
- **Console safety.** Control characters from repository text are replaced before printing,
  so file names cannot inject terminal escape sequences.

## Design decisions

Where the specification was ambiguous, the more conservative option was chosen:

- Anyone whose name matches an AI tool counts as an AI actor; such reviewers do not count.
- `Generated with <tool>` only counts when the tool is an AI actor ("Generated with protoc"
  does not).
- MAN-01 is N/A, not pass, when there is no git history or no AI-assisted commit.
- MAP-01 warns when no provenance signal exists at all, even if no AI was used.
- Manifest file entries need `path` and `tool`; a malformed `reviewed_at` drops the entry.
- Known-format secrets are always critical. "sk-" keys additionally require a digit and
  entropy >= 3.5 to avoid flagging ordinary identifiers. Values containing words such as
  `example`, `changeme` or `placeholder` are treated as placeholders.
- A manifest without a lockfile fails MAN-03; an unpinned requirement warns.
- If every control is N/A, the verdict is "Gaps" and the gate fails.
- `.venv`, `__pycache__`, `.tox` and similar directories are skipped in addition to the
  required list. This repository's policy also ignores `docs/demo/*` (generated reports).

## Development

```bash
python -m unittest discover        # 116 tests; git tests are skipped without git
python -m aigov scan .             # this repository must pass its own gate
python scripts/build_demo.py       # regenerate docs/demo/
```

Tests and examples build secret-like and CPF-like strings at runtime or use obviously fake
values, so the repository passes its own scan.

### Provenance of this repository

This code base was generated with an AI coding assistant and is declared in
[`.ai-provenance.json`](.ai-provenance.json). Until a maintainer reviews the files and records
`reviewed_by`, MAP-01 fails in the self-scan, which is the intended behaviour.
