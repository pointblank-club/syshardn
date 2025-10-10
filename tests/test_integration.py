import pytest
from pathlib import Path
import yaml
import tempfile
import os

from syshardn.core.os_detector import OSDetector
from syshardn.parsers.rule_loader import RuleLoader
from syshardn.executors.executor_factory import ExecutorFactory
from syshardn.reporters.report_generator import ReportGenerator, ReportFormat


@pytest.fixture
def test_rules_dir(tmp_path):
    """Create a temporary rules directory with sample rules."""
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
            'subcategory': 'Integration',
            'description': 'A simple test rule that runs echo',
            'severity': 'low',
            'tags': ['test', 'integration']
        },
        'audit': {
            'rationale': 'Test rule for integration testing',
            'cis_reference': 'N/A',
            'impact': 'None - test only'
        },
        'check': {
            'command': 'echo "test"',
            'expected': {
                'operator': 'contains',
                'type': 'string'
            },
            'timeout': 30
        },
        'remediation': {
            'command': 'echo "remediated"',
            'prerequisites': [],
            'backup_before': False,
            'verify_after': False,
            'requires_reboot': False,
            'timeout': 30
        },
        'hardening': {
            'basic': {
                'enabled': True,
                'value': 'test'
            },
            'moderate': {
                'enabled': True,
                'value': 'test'
            },
            'strict': {
                'enabled': True,
                'value': 'test'
            }
        }
    }
    
    rule_file = linux_dir / "TEST-001-echo-test.yaml"
    with open(rule_file, 'w') as f:
        yaml.dump(rule_data, f)
    
    return rules_dir


def test_full_workflow_os_detection():
    """Test OS detection functionality."""
    detector = OSDetector()

    os_type = detector.get_os_type()
    assert os_type in ['windows', 'linux', 'macos', 'darwin', 'unknown']
    
    version = detector.get_version()
    assert version is not None


def test_full_workflow_rule_loading(test_rules_dir):
    """Test complete rule loading workflow."""
    loader = RuleLoader(str(test_rules_dir))

    detector = OSDetector()
    current_os = detector.get_os_type()

    all_rules = loader.load_rules(os_type=current_os)
    assert len(all_rules) >= 0

    all_rules_unfiltered = loader.load_rules()
    assert len(all_rules_unfiltered) >= 1


def test_full_workflow_rule_execution(test_rules_dir):
    """Test complete rule execution workflow."""
    detector = OSDetector()
    current_os = detector.get_os_type()
    
    loader = RuleLoader(str(test_rules_dir))
    filtered_rules = loader.load_rules(os_type=current_os)
    
    if len(filtered_rules) == 0:
        pytest.skip(f"No rules available for platform: {current_os}")

    executor = ExecutorFactory.create_executor(current_os)

    if len(filtered_rules) > 0:
        rule = filtered_rules[0]
        result = executor.check_rule(rule, "moderate")
        
        assert 'rule_id' in result
        assert 'status' in result


def test_full_workflow_report_generation(test_rules_dir, tmp_path):
    """Test complete workflow including report generation."""
    detector = OSDetector()
    current_os = detector.get_os_type()
    
    loader = RuleLoader(str(test_rules_dir))
    filtered_rules = loader.load_rules(os_type=current_os)
    
    if len(filtered_rules) == 0:
        pytest.skip(f"No rules available for platform: {current_os}")

    executor = ExecutorFactory.create_executor(current_os)
    results = []
    
    for rule in filtered_rules:
        result = executor.check_rule(rule, "moderate")
        results.append(result)

    report_dir = tmp_path / "reports"
    report_generator = ReportGenerator(output_dir=report_dir)

    json_file = report_generator.generate(
        results,
        ReportFormat.JSON,
        report_dir / "test.json",
        "Integration Test Report"
    )
    assert json_file is not None
    assert json_file.exists()

    csv_file = report_generator.generate(
        results,
        ReportFormat.CSV,
        report_dir / "test.csv"
    )
    assert csv_file is not None
    assert csv_file.exists()

    html_file = report_generator.generate(
        results,
        ReportFormat.HTML,
        report_dir / "test.html",
        "Integration Test HTML Report"
    )
    assert html_file is not None
    assert html_file.exists()

    md_file = report_generator.generate(
        results,
        ReportFormat.MARKDOWN,
        report_dir / "test.md",
        "Integration Test MD Report"
    )
    assert md_file is not None
    assert md_file.exists()


def test_executor_factory():
    """Test executor factory."""
    linux_executor = ExecutorFactory.create_executor('linux')
    assert linux_executor is not None
    
    windows_executor = ExecutorFactory.create_executor('windows')
    assert windows_executor is not None

    with pytest.raises(ValueError):
        ExecutorFactory.create_executor('unknown_os')


def test_rule_validation(test_rules_dir):
    """Test rule validation."""
    loader = RuleLoader(str(test_rules_dir))

    valid_rule = {
        'metadata': {
            'benchmark': 'Test Benchmark v1.0',
            'os': 'linux',
            'version': '1.0'
        },
        'rule': {
            'id': 'VALID-001',
            'category': 'Test',
            'subcategory': 'Validation',
            'description': 'This is a valid rule',
            'severity': 'medium'
        },
        'check': {
            'command': 'echo test',
            'expected': {
                'operator': '==',
                'type': 'string'
            },
            'timeout': 30
        },
        'remediation': {
            'command': 'echo fix',
            'timeout': 30
        },
        'hardening': {
            'basic': {'enabled': True, 'value': 'test'},
            'moderate': {'enabled': True, 'value': 'test'},
            'strict': {'enabled': True, 'value': 'test'}
        }
    }
    
    assert loader.validate_rule(valid_rule) is True

    invalid_rule = {
        'rule': {
            'id': 'INVALID-001',
            'description': 'Invalid Rule'
        }
    }
    
    assert loader.validate_rule(invalid_rule) is False
