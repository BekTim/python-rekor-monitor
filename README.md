# Python Rekor Monitor

A command-line tool that checks the integrity of the public
[Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) transparency log.

It can:

- **fetch the latest checkpoint** (tree ID, tree size, root hash) of the log;
- **verify inclusion** of a signed artifact: check the artifact's signature with the
  certificate stored in the Rekor entry, then check the entry's Merkle inclusion proof
  ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962));
- **verify consistency** between a checkpoint you saved earlier and the latest one,
  proving the log was only appended to and never rewritten.

Built for NYU CS-GY 9223 Software Supply Chain Security.

## Installation

Requirements: Python 3.12+ and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/BekTim/python-rekor-monitor.git
cd python-rekor-monitor
poetry install
```

## Usage

```bash
# Latest checkpoint (add -d to also save it to checkpoint.json)
poetry run python main.py -c

# Inclusion: verify artifact.md against Rekor entry 3078541822
poetry run python main.py --inclusion 3078541822 --artifact artifact.md

# Consistency: compare an older checkpoint with the latest one
poetry run python main.py --consistency \
    --tree-id <treeID> --tree-size <treeSize> --root-hash <rootHash>
```

Use the `treeID`, `treeSize` and `rootHash` values from an earlier `-c` run.
Add `-d` to any command for debug output.

## Development

```bash
poetry install           # installs runtime and dev dependencies
pre-commit install       # enables the secret-scanning hook (needs trufflehog)
```

Checks used in this project:

| Tool | Command |
|---|---|
| Formatter | `poetry run ruff format .` |
| Linter | `poetry run ruff check` |
| Type checker | `poetry run mypy main.py merkle_proof.py util.py` |
| Security (SAST) | `poetry run bandit -c pyproject.toml -r .` |
| Tests + coverage | `poetry run pytest` |

All of them must pass before a pull request is merged.
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security

Please do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
