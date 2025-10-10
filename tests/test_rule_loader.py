import pytest
from pathlib import Path
import yaml

from syshardn.parsers.rule_loader import RuleLoader


@pytest.fixture
def sample_rule_file(tmp_path):
    """Create a sample rule file for testing."""
    rules_dir = tmp_path / "rules"
    linux_dir = rules_dir / "linux"
    linux_dir.mkdir(parents=True, exist_ok=True)

    rule_data = {
        'metadata': {
            'benchmark': 'Test Benchmark v1.0',
            'os': 'linux',
            'version': '1.0',
            'author': 'Test Suite',
            'date': '2025-10-05'
        },
        'rule': {
            'id': 'TEST-001',
            'category': 'Test',
            'subcategory': 'Unit Testing',
            'description': 'A test rule for unit testing',
            'severity': 'low',
            'tags': ['test']
        },
        'audit': {
            'rationale': 'Test rule',
            'cis_reference': 'N/A',
            'impact': 'None'
        },
        'check': {
            'command': 'echo "test"',
            'expected': {
                'operator': '==',
                'type': 'string'
            },
            'timeout': 30
        },
        'remediation': {
            'command': 'echo "fix"',
            'prerequisites': [],
            'backup_before': False,
            'verify_after': False,
            'requires_reboot': False,
            'timeout': 30
        },
        'hardening': {
            'basic': {'enabled': True, 'value': 'test'},
            'moderate': {'enabled': True, 'value': 'test'},
            'strict': {'enabled': True, 'value': 'test'}
        }
    }
    
    rule_file = linux_dir / "TEST-001-test-rule.yaml"
    with open(rule_file, 'w') as f:
        yaml.dump(rule_data, f)
    
    return rule_file


@pytest.fixture
def rule_loader(tmp_path):
    """Create a RuleLoader instance with proper directory structure."""
    rules_dir = tmp_path / "rules"
    linux_dir = rules_dir / "linux"
    linux_dir.mkdir(parents=True, exist_ok=True)

    windows_dir = rules_dir / "windows"
    windows_dir.mkdir(parents=True, exist_ok=True)
    
    return RuleLoader(str(rules_dir))


def test_load_single_rule(rule_loader, sample_rule_file):
    """Test loading a single rule file."""
    rules = rule_loader.load_rules(os_type="linux")
    
    assert len(rules) == 1
    rule = rules[0]

    assert 'rule' in rule
    assert rule['rule']['id'] == 'TEST-001'
    assert rule['rule']['description'] == 'A test rule for unit testing'


def test_load_multiple_rules(rule_loader, tmp_path):
    """Test loading multiple rule files."""
    linux_dir = Path(rule_loader.rules_dir) / "linux"

    for i in range(3):
        rule_data = {
            'metadata': {'benchmark': 'Test Benchmark v1.0', 'os': 'linux', 'version': '1.0'},
            'rule': {
                'id': f'LNX-{i:03d}',
                'category': 'Test',
                'subcategory': 'Multi',
                'description': f'Test rule number {i}',
                'severity': 'low'
            },
            'audit': {'rationale': 'Test', 'cis_reference': 'N/A', 'impact': 'None'},
            'check': {
                'command': f'echo "test-{i}"',
                'expected': {'operator': '==', 'type': 'string'},
                'timeout': 30
            },
            'remediation': {
                'command': f'echo "fix-{i}"',
                'timeout': 30
            },
            'hardening': {
                'basic': {'enabled': True, 'value': f'test-{i}'},
                'moderate': {'enabled': True, 'value': f'test-{i}'},
                'strict': {'enabled': True, 'value': f'test-{i}'}
            }
        }
        
        rule_file = linux_dir / f"LNX-{i:03d}-test.yaml"
        with open(rule_file, 'w') as f:
            yaml.dump(rule_data, f)

    rules = rule_loader.load_rules(os_type="linux")

    assert len(rules) >= 3
    assert all('rule' in rule for rule in rules)


def test_load_rules_from_directory(rule_loader, tmp_path):
    """Test loading all rules from a directory."""
    linux_dir = Path(rule_loader.rules_dir) / "linux"

    for i in range(2):
        rule_data = {
            'metadata': {'benchmark': 'Test Benchmark v1.0', 'os': 'linux', 'version': '1.0'},
            'rule': {
                'id': f'LNX-DIR-{i:03d}',
                'category': 'Test',
                'subcategory': 'Directory',
                'description': f'Directory test rule {i}',
                'severity': 'low'
            },
            'audit': {'rationale': 'Test', 'cis_reference': 'N/A', 'impact': 'None'},
            'check': {
                'command': 'echo "test"',
                'expected': {'operator': '==', 'type': 'string'},
                'timeout': 30
            },
            'remediation': {'command': 'echo "fix"', 'timeout': 30},
            'hardening': {
                'basic': {'enabled': True, 'value': 'test'},
                'moderate': {'enabled': True, 'value': 'test'},
                'strict': {'enabled': True, 'value': 'test'}
            }
        }
        
        rule_file = linux_dir / f"LNX-DIR-{i:03d}.yaml"
        with open(rule_file, 'w') as f:
            yaml.dump(rule_data, f)

    rules = rule_loader.load_rules(os_type="linux")
    
    assert len(rules) >= 2


def test_filter_rules_by_platform(rule_loader, tmp_path):
    """Test filtering rules by platform."""
    linux_dir = Path(rule_loader.rules_dir) / "linux"
    windows_dir = Path(rule_loader.rules_dir) / "windows"

    linux_rule = {
        'metadata': {'benchmark': 'Test Benchmark v1.0', 'os': 'linux', 'version': '1.0'},
        'rule': {
            'id': 'LNX-PLAT-001',
            'category': 'Test',
            'description': 'Linux platform test',
            'severity': 'low'
        },
        'audit': {'rationale': 'Test', 'cis_reference': 'N/A', 'impact': 'None'},
        'check': {'command': 'echo "test"', 'expected': {'operator': '==', 'type': 'string'}, 'timeout': 30},
        'remediation': {'command': 'echo "fix"', 'timeout': 30},
        'hardening': {
            'basic': {'enabled': True, 'value': 'test'},
            'moderate': {'enabled': True, 'value': 'test'},
            'strict': {'enabled': True, 'value': 'test'}
        }
    }
    with open(linux_dir / "LNX-PLAT-001.yaml", 'w') as f:
        yaml.dump(linux_rule, f)

    windows_rule = {
        'metadata': {'benchmark': 'Test Benchmark v1.0', 'os': 'windows', 'version': '1.0'},
        'rule': {
            'id': 'WIN-PLAT-001',
            'category': 'Test',
            'description': 'Windows platform test',
            'severity': 'low'
        },
        'audit': {'rationale': 'Test', 'cis_reference': 'N/A', 'impact': 'None'},
        'check': {'command': 'echo "test"', 'expected': {'operator': '==', 'type': 'string'}, 'timeout': 30},
        'remediation': {'command': 'echo "fix"', 'timeout': 30},
        'hardening': {
            'basic': {'enabled': True, 'value': 'test'},
            'moderate': {'enabled': True, 'value': 'test'},
            'strict': {'enabled': True, 'value': 'test'}
        }
    }
    with open(windows_dir / "WIN-PLAT-001.yaml", 'w') as f:
        yaml.dump(windows_rule, f)

    linux_rules = rule_loader.load_rules(os_type="linux")
    windows_rules = rule_loader.load_rules(os_type="windows")
    
    assert len(linux_rules) >= 1
    assert len(windows_rules) >= 1


def test_filter_rules_by_level(rule_loader, tmp_path):
    """Test filtering rules by hardening level."""
    linux_dir = Path(rule_loader.rules_dir) / "linux"

    severities = ['low', 'medium', 'high']
    for i, severity in enumerate(severities):
        rule_data = {
            'metadata': {'benchmark': 'Test Benchmark v1.0', 'os': 'linux', 'version': '1.0'},
            'rule': {
                'id': f'LNX-LEV-{i:03d}',
                'category': 'Test',
                'description': f'Level test rule {i}',
                'severity': severity
            },
            'audit': {'rationale': 'Test', 'cis_reference': 'N/A', 'impact': 'None'},
            'check': {'command': 'echo "test"', 'expected': {'operator': '==', 'type': 'string'}, 'timeout': 30},
            'remediation': {'command': 'echo "fix"', 'timeout': 30},
            'hardening': {
                'basic': {'enabled': True if i <= 1 else False, 'value': 'test'},
                'moderate': {'enabled': True if i <= 2 else False, 'value': 'test'},
                'strict': {'enabled': True, 'value': 'test'}
            }
        }
        
        rule_file = linux_dir / f"LNX-LEV-{i:03d}.yaml"
        with open(rule_file, 'w') as f:
            yaml.dump(rule_data, f)

    all_rules = rule_loader.load_rules(os_type="linux")

    assert len(all_rules) >= 3


def test_validate_rule_schema(rule_loader):
    """Test rule schema validation."""
    valid_rule = {
        'metadata': {
            'benchmark': 'Test Benchmark v1.0',
            'os': 'linux',
            'version': '1.0'
        },
        'rule': {
            'id': 'VAL-001',
            'category': 'Test',
            'subcategory': 'Validation',
            'description': 'A valid rule',
            'severity': 'medium'
        },
        'audit': {
            'rationale': 'Test validation',
            'cis_reference': 'N/A',
            'impact': 'None'
        },
        'check': {
            'command': 'echo "test"',
            'expected': {
                'operator': '==',
                'type': 'string'
            },
            'timeout': 30
        },
        'remediation': {
            'command': 'echo "fix"',
            'timeout': 30
        },
        'hardening': {
            'basic': {'enabled': True, 'value': 'test'},
            'moderate': {'enabled': True, 'value': 'test'},
            'strict': {'enabled': True, 'value': 'test'}
        }
    }
    
    assert rule_loader.validate_rule(valid_rule) is True

    invalid_rule = {
        'rule': {
            'id': 'INV-001',
            'description': 'Invalid Rule'
        }
    }
    
    assert rule_loader.validate_rule(invalid_rule) is False


def test_load_invalid_yaml(rule_loader, tmp_path):
    """Test handling of invalid YAML files."""
    linux_dir = Path(rule_loader.rules_dir) / "linux"

    invalid_file = linux_dir / "LNX-INVALID.yaml"
    with open(invalid_file, 'w') as f:
        f.write("invalid: yaml: content: [[[")

    rules = rule_loader.load_rules(os_type="linux")

    assert isinstance(rules, list)


def test_load_nonexistent_file(rule_loader, tmp_path):
    """Test handling of non-existent rule directories."""
    rules = rule_loader.load_rules(os_type="nonexistent")
    
    assert isinstance(rules, list)
    assert len(rules) == 0


def test_filter_by_tags(rule_loader, tmp_path):
    """Test filtering rules by tags."""
    linux_dir = Path(rule_loader.rules_dir) / "linux"
    
    tag_sets = [
        ['authentication', 'password'],
        ['filesystem', 'security'],
        ['authentication', 'audit']
    ]
    
    for i, tags in enumerate(tag_sets):
        rule_data = {
            'metadata': {'benchmark': 'Test Benchmark v1.0', 'os': 'linux', 'version': '1.0'},
            'rule': {
                'id': f'LNX-TAG-{i:03d}',
                'category': 'Test',
                'description': f'Tag test rule {i}',
                'severity': 'low',
                'tags': tags
            },
            'audit': {'rationale': 'Test', 'cis_reference': 'N/A', 'impact': 'None'},
            'check': {'command': 'echo "test"', 'expected': {'operator': '==', 'type': 'string'}, 'timeout': 30},
            'remediation': {'command': 'echo "fix"', 'timeout': 30},
            'hardening': {
                'basic': {'enabled': True, 'value': 'test'},
                'moderate': {'enabled': True, 'value': 'test'},
                'strict': {'enabled': True, 'value': 'test'}
            }
        }
        
        rule_file = linux_dir / f"LNX-TAG-{i:03d}.yaml"
        with open(rule_file, 'w') as f:
            yaml.dump(rule_data, f)
    
    all_rules = rule_loader.load_rules(os_type="linux")

    assert len(all_rules) >= 3

    tagged_rules = [r for r in all_rules if 'tags' in r.get('rule', {})]
    assert len(tagged_rules) >= 3
