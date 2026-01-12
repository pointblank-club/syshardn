
# SysHardn

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/pointblank-club/syshardn/actions/workflows/build.yml/badge.svg)](https://github.com/pointblank-club/syshardn/actions/workflows/build.yml)

SysHardn is a rule-based system hardening tool. It can audit a system against a set of rules and apply remediations with backups and rollback support.

Status: alpha. Treat it as a security tool that can change system configuration; review rules before applying.

## Features

- Rules are defined in YAML.
- Commands: `check`, `apply`, `report`, `rollback`, `list-rules`.
- Reporting formats: console, JSON, HTML, CSV, Markdown, PDF.
- Backups and rollback are supported when a rule provides rollback commands.

---

## Requirements

### System Requirements

#### Windows
- Windows 10 (1809+) or Windows 11
- PowerShell 5.1 or later
- Administrator privileges

#### Linux
- Ubuntu 20.04+, Debian 10+, RHEL/CentOS 8+, Fedora 36+
- Bash 4.0 or later

### Python
- Python 3.9 or higher
- pip for package management
- Virtual environment (recommended)

### Supported platforms

- Windows 10/11 (PowerShell required)
- Linux distributions listed in the rules metadata

---

## Quick start

### Installation

```bash
# Clone the repository
git clone https://github.com/pointblank-club/syshardn.git
cd syshardn

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies and the package
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

For development:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .
```

### Verify Installation

```bash
# Check version
syshardn --version

# View help
syshardn --help

# List available rules
syshardn list-rules
```

---

## Usage

### Basic Commands

#### Check Compliance

```bash
# Check all rules for your platform
syshardn check

# Check a specific hardening level
syshardn check --level moderate

# Check specific rules
syshardn check --rules WIN-001 --rules WIN-002

# Output results as JSON to console
syshardn check --json

# Write a report file from the check
syshardn check --report results.json
```

#### Apply Remediation

```bash
# Apply all rules for your platform at a hardening level
syshardn apply --level moderate

# Apply specific rules
syshardn apply --rules LNX-001 --rules LNX-002 --force

# Dry-run mode (show what would be done)
syshardn apply --dry-run
```

#### Generate Reports

```bash
# Generate a report file
syshardn report --format html --output report.html

# Generate JSON report file
syshardn report --format json --output report.json

# Generate CSV report for analysis
syshardn report --format csv --output report.csv

# Output report results as JSON to console
syshardn report --json
```

#### Rollback Changes

```bash
# List available backups
syshardn rollback --list

# Rollback the latest backup for a rule
syshardn rollback --rule-id WIN-001 --latest
```

#### Browse Rules

```bash
# List all rules
syshardn list-rules

# List rules for specific platform
syshardn list-rules --os-filter windows

# List rules by category
syshardn list-rules --category Filesystem

# List detailed view
syshardn list-rules --detailed
```

### Logging

```bash
# Enable debug logging
syshardn --log-level DEBUG check

# Log to file
syshardn --log-file syshardn.log check

# Verbose output
syshardn check --verbose
```

---

## Rules

Rules are YAML files under `rules/linux/` and `rules/windows/`.

To create a new rule, start from the template:

- `rules/templates/TEMPLATE.yaml`

---


## Testing

```bash
# Run the full test suite
python -m pytest
```

Install dev dependencies with:

```bash
pip install -r requirements-dev.txt
```

---

## Contributing

See `CONTRIBUTING.md`.

## License

[Apache License 2.0](LICENSE)

---

## Resources

- Rule template: `rules/templates/TEMPLATE.yaml`
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks/
- Issue tracker: https://github.com/pointblank-club/syshardn/issues

## Disclaimer

This tool makes significant changes to system configuration. Always:
- Test in non-production environments first
- Review rules before applying
- Maintain backups
- Understand the impact of each rule
- Have a rollback plan

The authors are not responsible for any system issues or data loss resulting from the use of this tool.

---
