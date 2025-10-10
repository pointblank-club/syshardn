"""
Pytest configuration and shared fixtures.
"""

import pytest
import sys
from pathlib import Path

src_dir = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_dir))


@pytest.fixture
def temp_backup_dir(tmp_path):
    """Create a temporary backup directory."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    return backup_dir


@pytest.fixture
def temp_log_dir(tmp_path):
    """Create a temporary log directory."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return log_dir


@pytest.fixture
def temp_report_dir(tmp_path):
    """Create a temporary report directory."""
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    return report_dir

def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "windows: marks tests as Windows-only (deselect with '-m \"not windows\"')"
    )
    config.addinivalue_line(
        "markers", "linux: marks tests as Linux-only (deselect with '-m \"not linux\"')"
    )
    config.addinivalue_line(
        "markers", "darwin: marks tests as macOS-only (deselect with '-m \"not darwin\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (deselect with '-m \"not integration\"')"
    )
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
