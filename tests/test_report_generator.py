import json
import pytest
from pathlib import Path
from datetime import datetime
from enum import Enum

from syshardn.reporters.report_generator import ReportGenerator, ReportFormat


@pytest.fixture
def sample_results():
    """Sample check results for testing."""
    return [
        {
            'rule_id': 'WIN-001',
            'title': 'Enforce password history',
            'description': 'Ensure password history is set to 24 or more passwords',
            'level': 'L1',
            'status': 'pass',
            'message': 'Password history is set to 24 passwords'
        },
        {
            'rule_id': 'WIN-002',
            'title': 'Maximum password age',
            'description': 'Ensure maximum password age is 365 or fewer days',
            'level': 'L1',
            'status': 'fail',
            'message': 'Current value: 400 days, Expected: <= 365 days'
        },
        {
            'rule_id': 'LNX-001',
            'title': 'Disable cramfs',
            'description': 'Ensure mounting of cramfs filesystems is disabled',
            'level': 'L1',
            'status': 'pass',
            'message': 'cramfs module is disabled'
        },
        {
            'rule_id': 'LNX-009',
            'title': 'Disable USB storage',
            'description': 'Ensure USB storage is disabled',
            'level': 'L2',
            'status': 'fail',
            'message': 'USB storage is not disabled'
        },
        {
            'rule_id': 'WIN-003',
            'title': 'Minimum password age',
            'description': 'Ensure minimum password age is set',
            'level': 'L1',
            'status': 'error',
            'message': 'Failed to execute check command: Access denied'
        }
    ]


@pytest.fixture
def report_generator(tmp_path):
    """Create a ReportGenerator instance with temporary output directory."""
    return ReportGenerator(output_dir=tmp_path / "reports")


def test_report_generator_initialization(tmp_path):
    """Test ReportGenerator initialization."""
    output_dir = tmp_path / "test_reports"
    generator = ReportGenerator(output_dir=output_dir)
    
    assert generator.output_dir == output_dir
    assert output_dir.exists()


def test_calculate_summary(report_generator, sample_results):
    """Test summary calculation."""
    summary = report_generator._calculate_summary(sample_results)
    
    assert summary['total'] == 5
    assert summary['passed'] == 2
    assert summary['failed'] == 2
    assert summary['errors'] == 1
    assert summary['compliance_rate'] == 40.0


def test_generate_json_report(report_generator, sample_results, tmp_path):
    """Test JSON report generation."""
    output_file = tmp_path / "reports" / "test_report.json"
    
    result_path = report_generator.generate(
        sample_results,
        format=ReportFormat.JSON,
        output_file=output_file,
        title="Test Compliance Report"
    )
    
    assert result_path == output_file
    assert output_file.exists()
    
    # Verify JSON content
    with open(output_file, 'r') as f:
        data = json.load(f)
    
    assert data['title'] == "Test Compliance Report"
    assert 'generated' in data
    assert 'summary' in data
    assert data['summary']['total'] == 5
    assert data['summary']['passed'] == 2
    assert len(data['results']) == 5


def test_generate_csv_report(report_generator, sample_results, tmp_path):
    """Test CSV report generation."""
    output_file = tmp_path / "reports" / "test_report.csv"
    
    result_path = report_generator.generate(
        sample_results,
        format=ReportFormat.CSV,
        output_file=output_file
    )
    
    assert result_path == output_file
    assert output_file.exists()

    with open(output_file, 'r') as f:
        lines = f.readlines()
    
    assert len(lines) == 6 
    assert 'rule_id,title,description,level,status' in lines[0]


def test_generate_html_report(report_generator, sample_results, tmp_path):
    """Test HTML report generation."""
    output_file = tmp_path / "reports" / "test_report.html"
    
    result_path = report_generator.generate(
        sample_results,
        format=ReportFormat.HTML,
        output_file=output_file,
        title="Test HTML Report"
    )
    
    assert result_path == output_file
    assert output_file.exists()

    with open(output_file, 'r') as f:
        content = f.read()
    
    assert '<!DOCTYPE html>' in content
    assert 'Test HTML Report' in content
    assert 'WIN-001' in content
    assert 'LNX-001' in content


def test_generate_markdown_report(report_generator, sample_results, tmp_path):
    """Test Markdown report generation."""
    output_file = tmp_path / "reports" / "test_report.md"
    
    result_path = report_generator.generate(
        sample_results,
        format=ReportFormat.MARKDOWN,
        output_file=output_file,
        title="Test Markdown Report"
    )
    
    assert result_path == output_file
    assert output_file.exists()

    with open(output_file, 'r') as f:
        content = f.read()
    
    assert '# Test Markdown Report' in content
    assert '## Summary' in content
    assert '| ID | Title | Level | Status | Details |' in content
    assert 'WIN-001' in content


def test_generate_console_report(report_generator, sample_results, capsys):
    """Test console report generation."""
    result = report_generator.generate(
        sample_results,
        format=ReportFormat.CONSOLE,
        title="Test Console Report"
    )

    assert result is None


def test_generate_remediation_report(report_generator, sample_results, tmp_path):
    """Test remediation report generation."""
    output_file = tmp_path / "reports" / "remediation_report.json"
    
    result_path = report_generator.generate_remediation_report(
        sample_results,
        format=ReportFormat.JSON,
        output_file=output_file
    )
    
    assert result_path == output_file
    assert output_file.exists()

    with open(output_file, 'r') as f:
        data = json.load(f)
    
    assert 'Remediation' in data['title']


def test_auto_generate_filename(report_generator, sample_results):
    """Test automatic filename generation when not provided."""
    result_path = report_generator.generate(
        sample_results,
        format=ReportFormat.JSON
    )
    
    assert result_path is not None
    assert result_path.exists()
    assert result_path.name.startswith('compliance_report_')
    assert result_path.suffix == '.json'


def test_empty_results(report_generator):
    """Test report generation with empty results."""
    empty_results = []
    
    summary = report_generator._calculate_summary(empty_results)
    
    assert summary['total'] == 0
    assert summary['passed'] == 0
    assert summary['failed'] == 0
    assert summary['errors'] == 0
    assert summary['compliance_rate'] == 0


def test_invalid_format(report_generator, sample_results):
    """Test handling of invalid report format."""
    class InvalidFormat(Enum):
        INVALID = "invalid"
    
    with pytest.raises(ValueError):
        report_generator.generate(
            sample_results,
            format=InvalidFormat.INVALID
        )
