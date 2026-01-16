import pytest
from click.testing import CliRunner

from syshardn.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.mark.parametrize(
    "args, substrings",
    [
        (["--version"], ["SysHardn", "version"]),
        (["--help"], ["Usage:", "Options:", "Commands:"]),
    ],
    # Optionally specify IDs for nicer pytest results
    ids=["version", "help"],
)
def test_cli_options(runner, args, substrings):
    result = runner.invoke(cli, args)

    assert result.exit_code == 0
    for substring in substrings:
        assert substring in result.output


@pytest.mark.parametrize(
    "command",
    [
        "check",
        "apply",
        "report",
        "rollback",
        "list-rules",
    ],
)
def test_cli_commands(runner, command):
    result = runner.invoke(cli, [command, "--help"])

    assert result.exit_code == 0
    assert "Usage:" in result.output
