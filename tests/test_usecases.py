""" Test the usecases supplied by the authentic application """
from protean.core.repository import repo_factory
from protean.core.tasklet import Tasklet
from protean.impl.repository.dict_repo import DictSchema

from authentic.entities import Account
from authentic.usecases import RegisterUseCase, RegisterRequestObject


class AccountSchema(DictSchema):
    """ Schema for the Dog Entity"""

    class Meta:
        """ Meta class for schema options"""
        entity = Account
        schema_name = 'accounts'


repo_factory.register(AccountSchema)


class TestAuthenticUsecases:
    """ Test the usecases of Authentic"""

    def test_register_usecase(self):
        """Test register account usecase of authentic"""
        payload = {
            'id': 1,
            'email': 'dummy@domain.com',
            'username': 'dummy',
            'password': 'duMmy@123'
        }
        response = Tasklet.perform(repo_factory, AccountSchema, RegisterUseCase,
                                   RegisterRequestObject, payload)
        assert response is not None
        assert response.success is True
        assert response.value.id == 1
        assert response.value.username == 'dummy'

        # Try to create another account with same email
        payload = {
            'id': 2,
            'email': 'dummy@domain.com',
            'username': 'dummy2',
            'password': 'duMmy@123'
        }
        response = Tasklet.perform(repo_factory, AccountSchema, RegisterUseCase,
                                   RegisterRequestObject, payload)
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {'email': 'Email already exists'}}

