# SysHardn - Multi-Platform System Hardening Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)

A comprehensive, rule-based system hardening tool that implements CIS Benchmarks and security best practices across Windows and Linux platforms.

## 🎯 Key Features

### 🖥️ OS Detection & Modular Engine
- **Automatic OS detection**: Windows, Linux, and macOS support
- **Platform-specific executors**: Optimized for each operating system
- **Extensible architecture**: Easy to add new platforms and rules
- **YAML-based rule system**: Human-readable configuration format

### 🔒 Security Checks & Remediation
- **Windows**: CIS Microsoft Windows Benchmarks
  - Account Policies (Password & Lockout)
  - Registry-based security settings
  - Service configurations
- **Linux**: CIS Linux Benchmarks
  - Kernel module restrictions
  - File system security
  - System service hardening
- **Automated compliance checking**: Run checks against all rules
- **One-click remediation**: Apply security fixes automatically
- **Granular control**: Select specific rules or categories

### 📊 Comprehensive Reporting
- **Multiple formats**:
  - Console output with rich formatting
  - JSON for programmatic processing
  - HTML with responsive design
  - CSV for data analysis
  - Markdown for documentation
- **Detailed metrics**:
  - Compliance rate calculation
  - Pass/fail status per rule
  - Error tracking and reporting
  - Before/after comparisons

### 🔄 Rollback Capability
- **Automatic backups**: Created before any changes
- **Complete rollback**: Restore previous configurations
- **Backup management**: Track and manage historical backups
- **Safe remediation**: Always reversible

### 🛠️ Developer-Friendly CLI
- **Intuitive commands**: `check`, `apply`, `report`, `rollback`, `list-rules`
- **Rich terminal UI**: Beautiful output with colors and tables
- **Flexible filtering**: By platform, level, tags, or specific IDs
- **Logging support**: Debug and audit trail capabilities
- **Scriptable**: Perfect for automation and CI/CD

---

## 📋 Requirements

### System Requirements

#### Windows
- Windows 10 (1809+) or Windows 11
- PowerShell 5.1 or later
- Administrator privileges

#### Linux
- Ubuntu 20.04+, Debian 10+, RHEL/CentOS 8+, Fedora 36+
- Bash 4.0 or later
- Root or sudo access

### Python Requirements
- Python 3.8 or higher
- pip for package management
- Virtual environment (recommended)

---

## 🚀 Quick Start

### Installation

#### Standard Installation

```bash
# Clone the repository
git clone https://github.com/Aswinr24/syshardn.git
cd syshardn

# Run the setup script
python setup.py

# Or manually:
pip install -r requirements.txt
pip install -e .
```

#### Development Installation

```bash
# Install with development dependencies
python setup.py --dev

# Or manually:
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

## 📖 Usage

### Basic Commands

#### Check Compliance

```bash
# Check all rules for your platform
syshardn check

# Check specific severity level
syshardn check --level L1

# Check specific rules
syshardn check --rules WIN-001,WIN-002

# Export results as JSON
syshardn check --format json --output results.json
```

#### Apply Remediation

```bash
# Apply all L1 rules (with confirmation)
syshardn apply --level moderate

# Apply specific rules without confirmation
syshardn apply --rules LNX-001,LNX-002 --yes

# Dry-run mode (show what would be done)
syshardn apply --dry-run
```

#### Generate Reports

```bash
# Generate console report
syshardn report

# Generate HTML report
syshardn report --format html --output report.html

# Generate JSON report
syshardn report --format json --output report.json

# Generate CSV report for analysis
syshardn report --format csv --output report.csv
```

#### Rollback Changes

```bash
# List available backups
syshardn rollback --list

# Rollback to specific backup
syshardn rollback --backup 20250102_143000

# Rollback specific rules
syshardn rollback --rules WIN-001,WIN-002
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

### Advanced Usage


#### Logging and Debugging

```bash
# Enable debug logging
syshardn check --log-level DEBUG

# Log to file
syshardn check --log-file /var/log/syshardn.log

# Verbose output
syshardn check -v

# Apply with confirmation prompts
syshardn apply --level moderate --interactive

# Schedule periodic checks
syshardn schedule --level basic --cron "0 2 * * *"

# Export results in JSON
syshardn check --output results.json --format json
```

---

## 📖 Rule Structure

Rules are defined in YAML format with a consistent schema across platforms. See `rules/SCHEMA.md` for complete documentation.

### Example Rule Structure

```yaml
metadata:
  benchmark: CIS Benchmark Name
  os: windows or linux
  versions: [supported versions]

rule:
  id: OS-NNN
  category: Security Category
  description: What this rule enforces
  severity: low | medium | high | critical
  
  hardening_levels:
    basic: {enabled: true, value: 12}
    moderate: {enabled: true, value: 18}
    strict: {enabled: true, value: 24}
  
  check:
    command: |
      # Command to check compliance
    expected: {type: number, operator: ">=", value: "{{hardening_value}}"}
  
  remediation:
    command: |
      # Command to apply hardening
    verify_after: true
  
  rollback:
    enabled: true
    backup_command: |
      # Backup current state
    restore_command: |
      # Restore from backup
```

---


## 🛡️ Supported Security Standards

- ✅ CIS Benchmarks (Windows 10/11, Linux distributions)
- ✅ NIST SP 800-53 (National Institute of Standards and Technology)
- ✅ ISO/IEC 27001 (Information Security Management)

---

## 📈 Rule Categories

### Windows (Annexure A)
1. Account Policies (Password & Lockout)
2. Local Policies (Audit, User Rights, Security Options)
3. Event Log Settings
4. System Services
5. Registry Settings
6. Windows Firewall
7. Advanced Audit Policies
8. Application Security
9. Data Protection

### Linux (Annexure B)
1. Filesystem Configuration
2. Services Management
3. Network Configuration
4. Logging and Auditing
5. Access Control
6. User Accounts and Environment
7. System Maintenance
8. Software Updates

---

## 🔄 Workflow

1. **Detection**: Automatically detect OS, version, and distribution
2. **Analysis**: Load applicable rules for the target system
3. **Assessment**: Check current compliance status
4. **Backup**: Create backup of current configuration
5. **Remediation**: Apply hardening rules based on selected level
6. **Verification**: Verify each change was applied successfully
7. **Reporting**: Generate comprehensive compliance report
8. **Logging**: Record all actions to audit trail

---

## 🧪 Testing

Tests live under the `tests/` directory. Current test files in this repository are:

- `tests/test_rule_loader.py`        # Unit tests for rule loading and validation
- `tests/test_report_generator.py`  # Unit tests for report generation (JSON/CSV/HTML/MD)
- `tests/test_integration.py`       # End-to-end integration tests

The project uses pytest and is configured by `pytest.ini`. The CI runs tests with coverage using:

```bash
python -m pytest tests/ -v --cov=src/syshardn --cov-report=term-missing
```

Quick local commands you can run now:

```bash
# Run the full test suite
pytest

# Run a single test file
pytest tests/test_rule_loader.py -q
pytest tests/test_report_generator.py -q
pytest tests/test_integration.py -q

# Run a single test case inside a file
pytest tests/test_rule_loader.py::test_load_single_rule -q
```

Developer notes:
- Install test/dev dependencies before running tests:

```bash
pip install -r requirements-dev.txt
```

---

## 📝 License

[MIT License](LICENSE)

---

## 🔗 Resources

- [Rule Template](rules/templates/TEMPLATE.yaml)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Issue Tracker](https://github.com/aswinr24/syshardn/issues)

---

## ⚠️ Disclaimer

This tool makes significant changes to system configuration. Always:
- Test in non-production environments first
- Review rules before applying
- Maintain backups
- Understand the impact of each rule
- Have a rollback plan.

The authors are not responsible for any system issues or data loss resulting from the use of this tool.

---
