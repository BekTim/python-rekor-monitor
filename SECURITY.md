# Security Policy

## Supported versions

Only the latest version on the `main` branch receives security fixes.

| Version | Supported |
|---|---|
| `main` (0.1.x) | ✅ |
| older commits | ❌ |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report them privately through GitHub:
**Security** tab → **Report a vulnerability**.

Please include:

- a description of the issue and its impact;
- steps to reproduce (commands, inputs, expected and actual output);
- the commit you tested.

## What to expect

- You will get an acknowledgement within **3 business days**.
- The issue will be assessed and, if confirmed, fixed in a private branch.
- The fix is released on `main`, and a GitHub Security Advisory is published
  crediting the reporter (unless you prefer to stay anonymous).

## Handling of secrets

This repository uses a [trufflehog](https://github.com/trufflesecurity/trufflehog)
pre-commit hook to stop credentials from being committed. If a secret is ever
committed anyway, it must be **revoked and rotated immediately**: removing it in a
later commit is not enough, because it stays in the git history.
