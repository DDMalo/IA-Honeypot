# Contributing to IA-Honeypot

Thanks for your interest in contributing! This guide explains how to set up the project and how changes are proposed.

## Development setup

Requirements: Python 3.12 and Git.

```bash
git clone git@github.com:DDMalo/IA-Honeypot.git
cd IA-Honeypot
python -m venv .venv
source .venv/bin/activate        # Windows (Git Bash): source .venv/Scripts/activate
pip install -e ".[dev]"
pytest
```

Never commit real secrets. Copy `.env.example` to `.env` and fill in your own values; `.env` is ignored by Git.

## Workflow
The `main` branch only contains stable releases. All work happens on `develop` through pull requests.

1. Pick an open issue (or open a new one describing the change).
2. 2. Create a branch from `develop` with a descriptive name:
   - `feat/<short-description>` for new functionality
   - `fix/<short-description>` for bug fixes
   - `docs/<short-description>` for documentation
   - `chore/<short-description>` for maintenance and tooling
3. Make your changes and add tests when possible.
4. Open a pull request that references the issue (for example, `Closes #12`).
5. Make sure all automated checks pass before merging.

## Commit messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add GeoIP enrichment
fix: handle sessions without commands
docs: update deployment guide
chore: configure pre-commit hooks
test: add parser tests for malformed lines
```

## Code style

- Code, comments and documentation are written in English.
- Formatting and linting are handled by `ruff`; type checking by `mypy`.
- Keep functions small and add type hints everywhere.

## Security

Please do not report security vulnerabilities through public issues. See [SECURITY.md](SECURITY.md).

Never commit malware samples, real attacker data containing IP addresses, or API keys.
