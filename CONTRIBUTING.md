# Contributing

Thanks for your interest in improving this project!

## Reporting issues

- Search existing issues first.
- For bugs, include the command you ran, the output you got, and what you expected.
- Link to the exact line of code when possible
  (click the line number on GitHub → **Reference in new issue**).
- **Security problems:** do not open a public issue, follow [SECURITY.md](SECURITY.md).

## Development setup

```bash
poetry install
pre-commit install
```

`pre-commit install` enables a [trufflehog](https://github.com/trufflesecurity/trufflehog)
hook that blocks commits containing secrets. You need the `trufflehog` binary installed.

## Pull requests

`main` is protected: every change goes through a pull request, and history is kept
linear (squash or rebase merges only).

1. Branch off an up-to-date `main`:
   `git switch main && git pull && git switch -c fix/short-description`
2. Keep each pull request focused on **one** change.
3. Reference the issue in the PR description: `Fixes #12`.
4. Make sure all checks below pass.

## Code style and checks

| Check | Command | Requirement |
|---|---|---|
| Formatting | `poetry run ruff format .` | no changes left |
| Linting | `poetry run ruff check` | 0 errors |
| Types | `poetry run mypy main.py merkle_proof.py util.py` | 0 errors (strict mode) |
| Security | `poetry run bandit -c pyproject.toml -r .` | no issues |
| Tests | `poetry run pytest` | all pass, coverage ≥ 75% |

- All functions have type annotations.
- New behaviour comes with tests. Tests must not use the network: mock the Rekor API.
- Never commit secrets, `.env` files or private keys.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):
`fix: ...`, `feat: ...`, `test: ...`, `docs: ...`, `chore: ...`, `style: ...`.
Describe **what changed**, e.g. `fix: validate Rekor response before using entry`.
