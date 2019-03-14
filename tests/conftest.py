"""Module to setup Factories and other required artifacts for tests"""
import os

from protean.core.repository import repo_factory
from protean.impl.repository.dict_repo import DictModel

from authentic.entities import Account
from authentic.entities import Session

base_dir = os.path.abspath(os.path.dirname(__file__))


# Setup the schemas used by the test cases
class AccountModel(DictModel):
    """ Schema for the Account Entity"""

    class Meta:
        """ Meta class for schema options"""
        entity = Account
        schema_name = 'accounts'


class SessionModel(DictModel):
    """ Schema for the Session Entity"""

    class Meta:
        """ Meta class for schema options"""
        entity = Session
        schema_name = 'sessions'


repo_factory.register(AccountModel)
repo_factory.register(SessionModel)
