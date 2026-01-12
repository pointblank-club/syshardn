# Contributing to SysHardn

This repository contains:
- Python package source in `src/syshardn/`
- Rule definitions in `rules/`
- Tests in `tests/`
- Build scripts: `build.sh` (Linux), `build.ps1` (Windows)
- CI workflows: `.github/workflows`

## Ground rules

- Keep changes small and focused.
- Prefer adding/adjusting tests for behavior changes.
- Avoid making hardening rules destructive by default. If a change can impact system availability, document the trade-off and add guardrails.

## Development setup

### Prerequisites

- Python 3.9+ (see `pyproject.toml` → `requires-python`)

### Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .
```

## Running tests

```bash
python -m pytest
```

## Code quality checks (local)

These tools are included in `requirements-dev.txt`.

```bash
black src tests
isort src tests
flake8 src tests
mypy src
```

## Contributing rules

Rules are YAML files under `rules/linux/` and `rules/windows/`.

### Start from the template

Use the tracked template:

- `rules/templates/TEMPLATE.yaml`

### Keep rule behavior consistent

- `metadata.os` should match the platform (e.g., `linux`, `windows`).
- `rule.id` should be unique and match the filename prefix.
- `rule.hardening_levels` is the source of the level-specific value used in `check.expected.value` and `remediation.command` via `{{hardening_value}}`.
- `check.command` should emit a clear, single value (stdout) for comparison.

### Safety and reversibility

- Prefer `remediation.backup_before: true` when edits are made to system files.
- If rollback is supported, ensure `rollback.backup_command` and `rollback.restore_command` are safe to run multiple times.

## Pull request guidelines

- Describe the “why” and the user-visible behavior change.
- Include OS assumptions (Linux distro, Windows version) when relevant.
- Add or update tests in `tests/`.
- Avoid mixing refactors and behavior changes in the same PR.

## CI expectations

GitHub Actions runs tests and produces build artifacts (see `.github/workflows/build.yml`).

Before opening a PR, it’s usually enough to run:

```bash
python -m pytest
```

## License

By contributing, you agree that your contributions are licensed under the terms in `LICENSE`.
