""" Test the usecases supplied by the authentic application """
from passlib.hash import pbkdf2_sha256

from protean.core.repository import repo
from protean.core.tasklet import Tasklet
from protean.services import email

from authentic.usecases import (CreateAccountRequestObject, CreateAccountUseCase,
                                UpdateAccountUseCase, UpdateAccountRequestObject,
                                ChangeAccountPasswordUseCase,
                                ChangeAccountPasswordRequestObject,
                                SendResetPasswordEmailRequestObject,
                                SendResetPasswordEmailUsecase,
                                ResetPasswordRequestObject, ResetPasswordUsecase,
                                LoginRequestObject, LoginUseCase,
                                LogoutRequestObject, LogoutUseCase)

from .conftest import AccountSchema


class TestAuthenticUsecases:
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

    def test_create_account_usecase(self):
        """Test create account usecase of authentic"""
        payload = {
            'email': 'dummy@domain.com',
            'username': 'dummy',
            'password': 'duMmy@123',
            'confirm_password': 'duMmy@123',
            'phone': '90080000800',
            'roles': ['ADMIN']
        }
        response = Tasklet.perform(repo, AccountSchema, CreateAccountUseCase,
                                   CreateAccountRequestObject, payload.copy())
        assert response is not None
        assert response.success is True
        assert response.value.username == 'dummy'

        # Check for validation errors - 1
        payload1 = {
            'email': 'dummy2@domain.com',
            'username': 'dummy2',
            'password': 'duMmy@123',
            'confirm_password': 'dummy@123',
            'phone': '90080000800',
        }
        response = Tasklet.perform(repo, AccountSchema, CreateAccountUseCase,
                                   CreateAccountRequestObject, payload1)
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {
                'confirm_password': 'Password and Confirm password must be same'
            },

        }

        # Check for validation errors - 2
        response = Tasklet.perform(repo, AccountSchema,
                                   CreateAccountUseCase,
                                   CreateAccountRequestObject, payload)
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {'email': 'Email already exists'}}

    def test_update_account_usecase(self):
        """Test update account usecase of authentic"""
        payload = {
            'identifier': self.account.id,
            'data': {
                'phone': '90070000700',
            }
        }
        response = Tasklet.perform(
            repo, AccountSchema, UpdateAccountUseCase,
            UpdateAccountRequestObject, payload.copy())

        assert response is not None
        assert response.success is True
        assert response.value.id == self.account.id
        assert response.value.phone == '90070000700'

    def test_change_password_usecase(self):
        """Test change password usecase of authentic"""
        payload = {
            'identifier': self.account.id,
            'data': {
                'current_password': 'duMmy@123',
                'new_password': 'duMmy@456',
                'confirm_password': 'duMmy@456',
            }
        }
        response = Tasklet.perform(
            repo, AccountSchema, ChangeAccountPasswordUseCase,
            ChangeAccountPasswordRequestObject, payload.copy())

        assert response is not None
        assert response.success is True

        # Try to update the password again
        payload = {
            'identifier': self.account.id,
            'data': {
                'current_password': 'duMmy@456',
                'new_password': 'duMmy@123',
                'confirm_password': 'duMmy@123',
            }
        }
        response = Tasklet.perform(
            repo, AccountSchema, ChangeAccountPasswordUseCase,
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
            repo, AccountSchema, SendResetPasswordEmailUsecase,
            SendResetPasswordEmailRequestObject, payload.copy())
        assert response is not None
        assert response.success is True

        # Make sure that the verification token is set
        account = repo.AccountSchema.get(self.account.id)
        assert account.verification_token is not None

        # Make sure that the reset email was sent
        assert email.outbox[-1].message() == (
            "johndoe@domain.com\n"
            "['johndoe@domain.com']\n"
            "Password Reset Request\n"
            f"Your reset secret token is {account.verification_token}")

        # Now reset the password with this token
        payload = {
            'token': account.verification_token,
            'data': {
                'new_password': 'duMmy@789',
                'confirm_password': 'duMmy@789',
            }
        }
        response = Tasklet.perform(
            repo, AccountSchema, ResetPasswordUsecase,
            ResetPasswordRequestObject, payload.copy())
        assert response is not None
        assert response.success is True

        # Make sure that the password has been updated
        account = repo.AccountSchema.get(self.account.id)
        assert len(account.password_history) == 2

    def test_login_usecase(self):
        """ Test login usecase of authentic """
        payload = {
            'username_or_email': 'johndoe@domain.com',
            'password': 'dummy@789',
        }
        response = Tasklet.perform(
            repo, AccountSchema, LoginUseCase,
            LoginRequestObject, payload.copy())
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {'password': 'Password is not correct.'}}

        payload['password'] = 'duMmy@789'
        response = Tasklet.perform(
            repo, AccountSchema, LoginUseCase, LoginRequestObject,
            payload.copy())
        assert response is not None
        assert response.success is True
        assert response.value.id == self.account.id
        assert response.value.email == 'johndoe@domain.com'

    def test_logout_usecase(self):
        """ Test logout usecase of authentic """
        payload = {
            'account': self.account
        }
        response = Tasklet.perform(
            repo, AccountSchema, LogoutUseCase, LogoutRequestObject,
            payload.copy())
        assert response is not None
        assert response.success is True
        assert response.value == {'message': 'success'}
