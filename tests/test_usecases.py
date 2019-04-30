""" Test the usecases supplied by the authentic application """
import pytest
from passlib.hash import pbkdf2_sha256
from protean.core.tasklet import Tasklet
from protean.services import email

from authentic.entities import Account
from authentic.usecases import ChangeAccountPasswordRequestObject
from authentic.usecases import ChangeAccountPasswordUseCase
from authentic.usecases import CreateAccountRequestObject
from authentic.usecases import CreateAccountUseCase
from authentic.usecases import LoginRequestObject
from authentic.usecases import LoginUseCase
from authentic.usecases import LogoutRequestObject
from authentic.usecases import LogoutUseCase
from authentic.usecases import ResetPasswordRequestObject
from authentic.usecases import ResetPasswordUsecase
from authentic.usecases import SendResetPasswordEmailRequestObject
from authentic.usecases import SendResetPasswordEmailUsecase
from authentic.usecases import UpdateAccountRequestObject
from authentic.usecases import UpdateAccountUseCase


class TestAuthenticUsecases:
    """ Test the usecases of Authentic"""

    @pytest.fixture(scope="function")
    def account(self):
        """Setup account to use in test cases"""
        account = Account.create({
            'email': 'johndoe@domain.com',
            'username': 'johndoe',
            'name': 'john doe',
            'password': pbkdf2_sha256.hash('duMmy@123'),
            'phone': '90080000800',
            'roles': ['ADMIN']
        })
        yield account

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
        response = Tasklet.perform(Account, CreateAccountUseCase,
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
        response = Tasklet.perform(Account, CreateAccountUseCase,
                                   CreateAccountRequestObject, payload1)
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {
                'confirm_password': 'Password and Confirm password must be same'
            },

        }

        # Check for validation errors - 2
        response = Tasklet.perform(Account, CreateAccountUseCase,
                                   CreateAccountRequestObject, payload)
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {'email': 'Email already exists'}}

    def test_update_account_usecase(self, account):
        """Test update account usecase of authentic"""
        payload = {
            'identifier': account.id,
            'data': {
                'phone': '90070000700',
            }
        }
        response = Tasklet.perform(
            Account, UpdateAccountUseCase,
            UpdateAccountRequestObject, payload.copy())

        assert response is not None
        assert response.success is True
        assert response.value.id == account.id
        assert response.value.phone == '90070000700'

    def test_change_password_usecase(self, account):
        """Test change password usecase of authentic"""
        payload = {
            'identifier': account.id,
            'data': {
                'current_password': 'duMmy@123',
                'new_password': 'duMmy@456',
                'confirm_password': 'duMmy@456',
            }
        }
        response = Tasklet.perform(
            Account, ChangeAccountPasswordUseCase,
            ChangeAccountPasswordRequestObject, payload.copy())

        assert response is not None
        assert response.success is True

        # Try to update the password again
        payload = {
            'identifier': account.id,
            'data': {
                'current_password': 'duMmy@456',
                'new_password': 'duMmy@123',
                'confirm_password': 'duMmy@123',
            }
        }
        response = Tasklet.perform(
            Account, ChangeAccountPasswordUseCase,
            ChangeAccountPasswordRequestObject, payload.copy())

        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422,
            'message': {'new_password': 'Password should not match previously '
                                        'used passwords'}}

    def test_password_reset_usecase(self, account):
        """ Test resetting a password using an email link """
        payload = {
            'email': 'johndoe@domain.com',
        }
        response = Tasklet.perform(
            Account, SendResetPasswordEmailUsecase,
            SendResetPasswordEmailRequestObject, payload.copy())
        assert response is not None
        assert response.success is True

        # Make sure that the verification token is set
        account = Account.get(account.id)
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
            Account, ResetPasswordUsecase,
            ResetPasswordRequestObject, payload.copy())
        assert response is not None
        assert response.success is True

        # Make sure that the password has been updated
        account = Account.get(account.id)
        assert len(account.password_history) == 1

    def test_login_usecase(self, account):
        """ Test login usecase of authentic """
        payload = {
            'username_or_email': 'johndoe@domain.com',
            'password': 'dummy@789',
        }
        response = Tasklet.perform(
            Account, LoginUseCase,
            LoginRequestObject, payload.copy())
        assert response is not None
        assert response.success is False
        assert response.value == {
            'code': 422, 'message': {'password': 'Password is not correct.'}}

        payload['password'] = 'duMmy@123'
        response = Tasklet.perform(
            Account, LoginUseCase, LoginRequestObject,
            payload.copy())
        assert response is not None
        assert response.success is True
        assert response.value.id == account.id
        assert response.value.email == 'johndoe@domain.com'

    def test_logout_usecase(self, account):
        """ Test logout usecase of authentic """
        payload = {
            'account': account
        }
        response = Tasklet.perform(
            Account, LogoutUseCase, LogoutRequestObject, payload.copy())
        assert response is not None
        assert response.success is True
        assert response.value == {'message': 'success'}
