""" Test the usecases supplied by the authentic application """
import base64

from passlib.hash import pbkdf2_sha256

from protean.core.tasklet import Tasklet
from protean.core.repository import repo_factory

from authentic.backends import basic
from .conftest import AccountSchema


class TestAuthenticBackends:
    """ Test the usecases of Authentic"""

    @classmethod
    def setup_class(cls):
        """ Setup instructions for this test case set """
        cls.account = repo_factory.AccountSchema.create({
            'id': 10,
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
        repo_factory.AccountSchema.delete(10)

    def test_basic_backend(self):
        """ Test http basic authentication backend """
        payload = {
            'auth_scheme': 'basic',
            'credentials': base64.b64encode(b'johndoe@domain.com:duMmy@789'),
        }
        print(base64.b64decode(payload['credentials']))
        response = Tasklet.perform(
            repo_factory, AccountSchema, basic.AuthenticationUseCase,
            basic.AuthenticationRequestObject, payload.copy())
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {'password': 'Password is not correct.'}}

