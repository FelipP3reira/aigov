# Security policy

## Reporting a vulnerability
Please report vulnerabilities privately through GitHub's "Report a vulnerability" (private
security advisory) on this repository. Do not open a public issue.

Include the aigov version, the command you ran and, if possible, a minimal repository that
reproduces the problem. Do not include real secrets or personal data in the report.

## What counts as a vulnerability
aigov is designed to be read-only and to never execute code from the repository it scans.
Examples of security bugs:

- aigov executing, importing or following symlinks into the scanned repository;
- a secret or personal data value appearing unmasked in the console, JSON or HTML output;
- repository content (file names, commit messages) injecting HTML or script into the report;
- git configuration in the scanned repository causing a command to run.

## Response
Maintainers acknowledge reports within five business days, agree on a fix and disclosure date
with the reporter, and publish an advisory with the release that fixes the issue.
