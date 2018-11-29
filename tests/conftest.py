"""Module to setup Factories and other required artifacts for tests"""
import os

from protean.core.repository import repo
from protean.impl.repository.dict_repo import DictSchema

from authentic.entities import Account, Session

base_dir = os.path.abspath(os.path.dirname(__file__))


# Setup the schemas used by the test cases
class AccountSchema(DictSchema):
    """ Schema for the Account Entity"""

    class Meta:
        """ Meta class for schema options"""
        entity = Account
        schema_name = 'accounts'


class SessionSchema(DictSchema):
    """ Schema for the Session Entity"""

    class Meta:
        """ Meta class for schema options"""
        entity = Session
        schema_name = 'sessions'


repo.register(AccountSchema)
repo.register(SessionSchema)
