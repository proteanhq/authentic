"""Module to setup Factories and other required artifacts for tests"""
import os

import pytest


base_dir = os.path.abspath(os.path.dirname(__file__))


def pytest_addoption(parser):
    """Additional options for running tests with pytest"""
    parser.addoption(
        "--slow", action="store_true", default=False, help="run slow tests"
    )


def pytest_collection_modifyitems(config, items):
    """Configure special markers on tests, so as to control execution"""
    if config.getoption("--slow"):
        # --slow given in cli: do not skip slow tests
        return
    skip_slow = pytest.mark.skip(reason="need --slow option to run")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)


@pytest.fixture(scope="session", autouse=True)
def register_models():
    """Register Test Models with Dict Repo

       Run only once for the entire test suite
    """
    from protean.core.repository import repo_factory
    from authentic.entities import Account
    from authentic.entities import Session

    repo_factory.register(Account)
    repo_factory.register(Session)


@pytest.fixture(autouse=True)
def run_around_tests():
    """Cleanup Database after each test run"""
    from protean.core.repository import repo_factory
    from authentic.entities import Account
    from authentic.entities import Session

    # A test function will be run at this point
    yield

    repo_factory.get_repository(Account).delete_all()
    repo_factory.get_repository(Session).delete_all()
