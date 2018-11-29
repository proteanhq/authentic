""" Test the usecases supplied by the authentic application """
import base64
from passlib.hash import pbkdf2_sha256

from protean.core.tasklet import Tasklet
from protean.core.repository import repo

from authentic.backends import basic
from ..conftest import AccountSchema


class TestAuthenticBackends:
    """ Test the usecases of Authentic"""

    @classmethod
    def setup_class(cls):
        """ Setup instructions for this test case set """
        cls.account = repo.AccountSchema.create({
            'email': 'johndoe@domain.com',
            'username': 'johndoe',
            'name': 'john doe',
            'password': pbkdf2_sha256.hash('duMmy@123'),
            'phone': '90080000800',
            'roles': ['ADMIN']
        })

    @classmethod
    def teardown_class(cls):
        """ Tear down instructions for this test case set"""
        repo.AccountSchema.delete(cls.account.id)

    def test_backend(self):
        """ Test http basic authentication backend """
        payload = {
            'auth_scheme': 'Basic',
            'credentials': base64.b64encode(b'johndoe@domain.com:dummy@789'),
        }
        response = Tasklet.perform(
            repo, AccountSchema, basic.AuthenticationUseCase,
            basic.AuthenticationRequestObject, payload.copy())
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {'password': 'Password is not correct.'}}

        # Try again with the right password
        payload['credentials'] = base64.b64encode(
            b'johndoe@domain.com:duMmy@123')
        response = Tasklet.perform(
            repo, AccountSchema, basic.AuthenticationUseCase,
            basic.AuthenticationRequestObject, payload.copy())
        assert response is not None
        assert response.success is True
        assert response.value.id is self.account.id
