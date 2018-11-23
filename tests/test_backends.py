""" Test the usecases supplied by the authentic application """
import base64
import os
from passlib.hash import pbkdf2_sha256

from protean.core.tasklet import Tasklet
from protean.core.repository import repo_factory
from protean.conf import active_config

from authentic.backends import basic, jwt
from authentic.usecases import LoginCallbackRequestObject
from .conftest import AccountSchema


class TestAuthenticBackends:
    """ Test the usecases of Authentic"""

    @classmethod
    def setup_class(cls):
        """ Setup instructions for this test case set """
        cls.account = repo_factory.AccountSchema.create({
            'email': 'johndoe@domain.com',
            'username': 'johndoe',
            'name': 'john doe',
            'password': pbkdf2_sha256.hash('duMmy@123'),
            'phone': '90080000800',
            'roles': ['ADMIN']
        })
        cls.base_dir = os.path.abspath(os.path.dirname(__file__))

    @classmethod
    def teardown_class(cls):
        """ Tear down instructions for this test case set"""
        repo_factory.AccountSchema.delete(cls.account.id)

    def test_basic_backend(self):
        """ Test http basic authentication backend """
        payload = {
            'auth_scheme': 'Basic',
            'credentials': base64.b64encode(b'johndoe@domain.com:dummy@789'),
        }
        response = Tasklet.perform(
            repo_factory, AccountSchema, basic.AuthenticationUseCase,
            basic.AuthenticationRequestObject, payload.copy())
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {'password': 'Password is not correct.'}}

        # Try again with the right password
        payload['credentials'] = base64.b64encode(
            b'johndoe@domain.com:duMmy@123')
        response = Tasklet.perform(
            repo_factory, AccountSchema, basic.AuthenticationUseCase,
            basic.AuthenticationRequestObject, payload.copy())
        assert response is not None
        assert response.success is True
        assert response.value.id is self.account.id

    def test_jwt_backend(self):
        """ Test jwt authentication backend """

        # Run the login callback usecase
        payload = {
            'account': repo_factory.AccountSchema.get(self.account.id)
        }
        response = Tasklet.perform(
            repo_factory, AccountSchema, jwt.LoginCallbackUseCase,
            LoginCallbackRequestObject, payload.copy())

        assert response is not None
        assert response.success is True
        access_token = response.value.get('access_token')
        assert access_token is not None

        # Use the token for authentication
        payload = {
            'auth_scheme': 'Bearer',
            'credentials': 'xxxxxxxxxxxxxxxxx',
        }
        response = Tasklet.perform(
            repo_factory, AccountSchema, jwt.AuthenticationUseCase,
            jwt.AuthenticationRequestObject, payload.copy())
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422,
            'message':
                {'credentials': 'Invalid JWT Token. Not enough segments'}}

        # Try again with the correct token
        payload['credentials'] = access_token
        response = Tasklet.perform(
            repo_factory, AccountSchema, jwt.AuthenticationUseCase,
            jwt.AuthenticationRequestObject, payload.copy())
        assert response is not None
        assert response.success is True

    def test_jwt_asymmetric_backend(self):
        """ Test jwt authentication backend with asymmetric alg"""
        # Update the config settings
        active_config.JWT_ALGORITHM = 'RS256'
        active_config.JWT_PRIVATE_KEY = os.path.join(
            self.base_dir, 'support/jwt_private_key.pem')
        active_config.JWT_PUBLIC_KEY = os.path.join(
            self.base_dir, 'support/jwt_public_key.pub')

        # Run the login callback usecase
        payload = {
            'account': repo_factory.AccountSchema.get(self.account.id)
        }
        response = Tasklet.perform(
            repo_factory, AccountSchema, jwt.LoginCallbackUseCase,
            LoginCallbackRequestObject, payload.copy())

        assert response is not None
        assert response.success is True
        access_token = response.value.get('access_token')

        assert access_token is not None

        # Use the token for authentication
        payload = {
            'auth_scheme': 'Bearer',
            'credentials': access_token,
        }
        response = Tasklet.perform(
            repo_factory, AccountSchema, jwt.AuthenticationUseCase,
            jwt.AuthenticationRequestObject, payload.copy())
        assert response is not None
        assert response.success is True
