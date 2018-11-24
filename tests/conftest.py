"""Module to setup Factories and other required artifacts for tests"""

import os

os.environ['PROTEAN_CONFIG'] = 'tests.support.sample_config'

from protean.core.repository import repo
from protean.impl.repository.dict_repo import DictSchema

from authentic.entities import Account


# Setup the schemas used by the test cases

class AccountSchema(DictSchema):
    """ Schema for the Dog Entity"""

    class Meta:
        """ Meta class for schema options"""
        entity = Account
        schema_name = 'accounts'


repo.register(AccountSchema)
