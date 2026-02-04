# Branch Protection Baseline

This is the minimum protected-branch baseline for `main`.

## Required repository settings

- Require a pull request before merging
- Require approvals (minimum: 1; recommended: 2)
- Dismiss stale approvals when new commits are pushed
- Require conversation resolution before merge
- Require status checks to pass before merging
- Do not allow force pushes
- Do not allow branch deletion

## Required status checks

Use `config/required_checks.txt` as the source of truth.

## Audit command

With an admin-capable GitHub token:

```bash
REPO=<owner/repo> BRANCH=main scripts/check_branch_protection.sh
```

This compares configured checks against `config/required_checks.txt` and fails
if any required check is missing.
