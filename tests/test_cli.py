import pytest
from click.testing import CliRunner

from syshardn.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def runner():
    return CliRunner()


@pytest.mark.parametrize(
    "args",
    [
        ["--version"],
        ["--help"],
    ],
)
def test_cli_options(runner, args):
    result = runner.invoke(cli, args)

    assert result.exit_code == 0
    assert result.output


@pytest.mark.parametrize(
    "args",
    [
        # Use --help to verify command exists and parses options without running actual logic
        ["check", "--help"],
        ["apply", "--help"],
        ["report", "--help"],
        ["rollback", "--help"],
        ["list-rules", "--help"],
    ],
)
def test_cli_subcommands(runner, args):
    result = runner.invoke(cli, args)

    assert result.exit_code == 0
    assert result.output
