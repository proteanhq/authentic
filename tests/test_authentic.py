
from click.testing import CliRunner

from authentic.cli import main


def test_main():
    runner = CliRunner()
    result = runner.invoke(main, [])

    assert 'Utility commands for the authentic package' in result.output
    assert result.exit_code == 0
