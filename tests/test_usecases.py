""" Test the usecases supplied by the authentic application """
from passlib.hash import pbkdf2_sha256

from protean.core.repository import repo_factory
from protean.core.tasklet import Tasklet

from authentic.usecases import (CreateAccountRequestObject, CreateAccountUseCase,
                                UpdateAccountUseCase, UpdateAccountRequestObject,
                                ChangeAccountPasswordUseCase,
                                ChangeAccountPasswordRequestObject,
                                SendResetPasswordEmailRequestObject,
                                SendResetPasswordEmailUsecase,
                                ResetPasswordRequestObject, ResetPasswordUsecase,
                                LoginRequestObject, LoginUseCase)

from .conftest import AccountSchema


class TestAuthenticUsecases:
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

    def test_create_account_usecase(self):
        """Test create account usecase of authentic"""
        payload = {
            'id': 1,
            'email': 'dummy@domain.com',
            'username': 'dummy',
            'password': 'duMmy@123',
            'confirm_password': 'duMmy@123',
            'phone': '90080000800',
            'roles': ['ADMIN']
        }
        response = Tasklet.perform(repo_factory, AccountSchema, CreateAccountUseCase,
                                   CreateAccountRequestObject, payload.copy())
        assert response is not None
        assert response.success is True
        assert response.value.id == 1
        assert response.value.username == 'dummy'

        # Check for validation errors - 1
        payload1 = {
            'id': 2,
            'email': 'dummy2@domain.com',
            'username': 'dummy2',
            'password': 'duMmy@123',
            'confirm_password': 'dummy@123',
            'phone': '90080000800',
            'roles': ['ADMIN', 'Dummy']
        }
        response = Tasklet.perform(repo_factory, AccountSchema, CreateAccountUseCase,
                                   CreateAccountRequestObject, payload1)
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {
                'roles': 'Invalid role(s)',
                'confirm_password': 'Password and Confirm password must be same'
            },

        }

        # Check for validation errors - 2
        response = Tasklet.perform(repo_factory, AccountSchema,
                                   CreateAccountUseCase,
                                   CreateAccountRequestObject, payload)
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {'email': 'Email already exists'}}

        # Delete the account object
        repo_factory.AccountSchema.delete(1)

    def test_update_account_usecase(self):
        """Test update account usecase of authentic"""
        payload = {
            'identifier': 10,
            'phone': '90070000700',
        }
        response = Tasklet.perform(
            repo_factory, AccountSchema, UpdateAccountUseCase,
            UpdateAccountRequestObject, payload.copy())

        assert response is not None
        assert response.success is True
        assert response.value.id == 10
        assert response.value.phone == '90070000700'

    def test_change_password_usecase(self):
        """Test change password usecase of authentic"""
        payload = {
            'identifier': 10,
            'data': {
                'current_password': 'duMmy@123',
                'new_password': 'duMmy@456',
                'confirm_password': 'duMmy@456',
            }
        }
        response = Tasklet.perform(
            repo_factory, AccountSchema, ChangeAccountPasswordUseCase,
            ChangeAccountPasswordRequestObject, payload.copy())

        assert response is not None
        assert response.success is True

        # Try to update the password again
        payload = {
            'identifier': 10,
            'data': {
                'current_password': 'duMmy@456',
                'new_password': 'duMmy@123',
                'confirm_password': 'duMmy@123',
            }
        }
        response = Tasklet.perform(
            repo_factory, AccountSchema, ChangeAccountPasswordUseCase,
            ChangeAccountPasswordRequestObject, payload.copy())

        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422,
            'message': {'password': 'Password should not match previously '
                                    'used passwords'}}

    def test_password_reset_usecase(self):
        """ Test resetting a password using an email link """
        payload = {
            'email': 'johndoe@domain.com',
        }
        response = Tasklet.perform(
            repo_factory, AccountSchema, SendResetPasswordEmailUsecase,
            SendResetPasswordEmailRequestObject, payload.copy())
        assert response is not None
        assert response.success is True

        # Make sure that the verification token is set
        account = repo_factory.AccountSchema.get(10)
        assert account.verification_token is not None

        # Now reset the password with this token
        payload = {
            'token': account.verification_token,
            'data': {
                'new_password': 'duMmy@789',
                'confirm_password': 'duMmy@789',
            }
        }
        response = Tasklet.perform(
            repo_factory, AccountSchema, ResetPasswordUsecase,
            ResetPasswordRequestObject, payload.copy())
        assert response is not None
        assert response.success is True

        # Make sure that the password has been updated
        account = repo_factory.AccountSchema.get(10)
        assert len(account.password_history) == 2

    def test_login_usecase(self):
        """ Test login usecase of authentic """
        payload = {
            'username_or_email': 'johndoe@domain.com',
            'password': 'dummy@789',
        }
        account = repo_factory.AccountSchema.get(10)
        print(account.is_locked, account.is_active)
        response = Tasklet.perform(
            repo_factory, AccountSchema, LoginUseCase,
            LoginRequestObject, payload.copy())
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {'password': 'Password is not correct.'}}

        payload['password'] = 'duMmy@789'
        response = Tasklet.perform(
            repo_factory, AccountSchema, LoginUseCase,
            LoginRequestObject, payload.copy())
        assert response is not None
        assert response.success is True
        assert response.value.id == 10
        assert response.value.email == 'johndoe@domain.com'
