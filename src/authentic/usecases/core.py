""" Core Usecases for Account CRUD and Authentication Flows"""

import datetime
import uuid

from passlib.hash import pbkdf2_sha256
from protean.conf import active_config
from protean.core.exceptions import ConfigurationError
from protean.core.transport import InvalidRequestObject
from protean.core.transport import ResponseFailure
from protean.core.transport import ResponseSuccess
from protean.core.transport import ResponseSuccessCreated
from protean.core.transport import Status
from protean.core.transport import ValidRequestObject
from protean.core.usecase import UpdateRequestObject
from protean.core.usecase import UpdateUseCase
from protean.core.usecase import UseCase
from protean.utils.importlib import perform_import

from ..utils import get_account_entity
from ..utils import get_auth_backend
from ..utils import modify_password_history
from ..utils import validate_new_password
from .helper import VerifyTokenRequestObject
from .helper import VerifyTokenUseCase

Account = get_account_entity()


class CreateAccountRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for Creating Accounts
    """

    def __init__(self, entity_cls, data=None):
        """Initialize Request Object with form data"""
        self.entity_cls = entity_cls
        self.data = data

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()
        is_idp_login = False

        if 'is_idp' in adict and adict['is_idp']:
            is_idp_login = True

        if 'email' not in adict:
            invalid_req.add_error('email', 'Email is mandatory')
        elif 'username' not in adict and not is_idp_login:
            adict['username'] = adict['email'].split('@')[0]

        if not is_idp_login:
            if 'password' not in adict:
                invalid_req.add_error('password', 'Password is mandatory')
            if 'confirm_password' not in adict:
                invalid_req.add_error(
                    'confirm_password', 'Confirm password is mandatory')
            else:
                if adict['password'] != adict['confirm_password']:
                    invalid_req.add_error(
                        'confirm_password',
                        'Password and Confirm password must be same')
                else:
                    del adict['confirm_password']

        # Set the update datetime
        adict['updated_at'] = datetime.datetime.utcnow()

        if invalid_req.has_errors:
            return invalid_req

        return CreateAccountRequestObject(entity_cls, adict)


class CreateAccountUseCase(UseCase):
    """
    This class implements the usecase for creating an Account
    """

    def process_request(self, request_object):
        """Process Create Account Request"""
        data = request_object.data
        is_idp_login = request_object.data.get('is_idp', False)

        if Account.query.filter(email=data['email']):
            return ResponseFailure.build_unprocessable_error(
                {'email': 'Email already exists'})

        if not is_idp_login:
            if Account.query.filter(username=data['username']):
                return ResponseFailure.build_unprocessable_error(
                    {'username': 'Username already exists'})

            password_check = validate_new_password(data['password'], [])
            if not password_check['is_valid']:
                return ResponseFailure.build_unprocessable_error(
                    {'password': password_check['error']})

        data['password'] = pbkdf2_sha256.hash(data['password'])
        account = Account.create(data)

        return ResponseSuccessCreated(account)


class UpdateAccountRequestObject(UpdateRequestObject):
    """
    This class encapsulates the Request Object for Updating Account
    """

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()

        # Set the update datetime
        adict['data']['updated_at'] = datetime.datetime.utcnow()

        if invalid_req.has_errors:
            return invalid_req

        return super().from_dict(entity_cls, adict)


class UpdateAccountUseCase(UpdateUseCase):
    """
    This class implements the usecase for updating Account
    """

    def process_request(self, request_object):
        """Process update Account Request"""
        account_obj = Account.get(request_object.identifier)
        if request_object.data.get('email') and \
                account_obj.email != request_object.data.get('email') and \
                Account.query.filter(email=request_object.data['email']):
            return ResponseFailure.build_unprocessable_error(
                {'email': 'Email already exists'})

        # Remove fields that cannot be updated
        for field in ['password', 'username']:
            request_object.data.pop(field, None)

        return super().process_request(request_object)


class ChangeAccountPasswordRequestObject(ValidRequestObject):
    """
    This class implements the request object for changing account password
    """

    def __init__(self, entity_cls, identifier=None, data=None):
        """Initialize Request Object with form data"""
        self.entity_cls = entity_cls
        self.data = data
        self.identifier = identifier

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()
        data = adict['data']

        if 'identifier' not in adict:
            invalid_req.add_error('identifier', 'ID is mandatory')
        if 'current_password' not in data:
            invalid_req.add_error('current_password',
                                  'Current password is mandatory')
        new_password = data.get('new_password')
        if new_password is None:
            invalid_req.add_error('new_password', 'New password is mandatory')

        confirm_password = data.get('confirm_password')
        if confirm_password is None:
            invalid_req.add_error(
                'confirm_password', 'Confirm password is mandatory')

        if new_password and confirm_password and \
                new_password != confirm_password:
            invalid_req.add_error('confirm_password',
                                  'Password and Confirm password must be same')

        if invalid_req.has_errors:
            return invalid_req

        return ChangeAccountPasswordRequestObject(
            entity_cls, adict['identifier'], adict['data'])


class ChangeAccountPasswordUseCase(UseCase):
    """
    This class implements the usecase for updating Account
    """

    def process_request(self, request_object):
        """Process update Account Request"""

        identifier = request_object.identifier
        data = request_object.data
        account = Account.get(identifier)

        if pbkdf2_sha256.verify(data['current_password'], account.password):
            password_check = validate_new_password(
                data['new_password'], account.password_history)
            if password_check['is_valid']:
                password = pbkdf2_sha256.hash(data['new_password'])
                password_history = modify_password_history(
                    account.password,
                    account.password_history)
                account.update(
                    {'password': password,
                     'password_history': password_history})
                return ResponseSuccess(Status.SUCCESS, {"message": "Success"})
            else:
                return ResponseFailure.build_unprocessable_error(
                    {'new_password': password_check['error']})
        else:
            return ResponseFailure.build_unprocessable_error(
                {'current_password': 'Invalid Password'})


class SendResetPasswordEmailRequestObject(ValidRequestObject):
    """
    This class implements the request object for sending reset password email
    """

    def __init__(self, entity_cls, email=None):
        self.entity_cls = entity_cls
        self.email = email

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()
        if 'email' not in adict:
            invalid_req.add_error('email', 'Email is mandatory')

        if invalid_req.has_errors:
            return invalid_req

        return SendResetPasswordEmailRequestObject(entity_cls, adict['email'])


class SendResetPasswordEmailUsecase(UseCase):
    """
    This class implements the usecase for sending reset password email
    """

    def process_request(self, request_object):
        email = request_object.email
        account = Account.query.filter(email=email).first

        if account:
            token = str(uuid.uuid4())
            token_ts = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            account.update(
                {
                    "verification_token": token,
                    "token_timestamp": token_ts
                }
            )

            # Send the password request email
            email_builder = perform_import(active_config.RESET_EMAIL_CALLBACK)
            if not email_builder:
                raise ConfigurationError(
                    '`RESET_EMAIL_CALLBACK` config must be set to a '
                    'valid function.')
            email_msg = email_builder(account.email, token)
            email_msg.send()

            return ResponseSuccess(Status.SUCCESS, {"message": "Success"})
        else:
            return ResponseFailure.build_unprocessable_error(
                {'email': 'Account does not exist.'})


class ResetPasswordRequestObject(ValidRequestObject):
    """
    This class implements the request object for resetting password
    """

    def __init__(self, entity_cls, token=None, data=None):
        self.entity_cls = entity_cls
        self.data = data
        self.token = token

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()

        data = adict['data']

        if 'token' not in adict:
            invalid_req.add_error('token', 'Token is mandatory')
        new_password = data.get('new_password')
        if new_password is None:
            invalid_req.add_error('new_password', 'New password is mandatory')
        confirm_password = data.get('confirm_password')
        if confirm_password is None:
            invalid_req.add_error(
                'confirm_password', 'Confirm password is mandatory')

        if new_password and confirm_password and \
                new_password != confirm_password:
            invalid_req.add_error('new_password',
                                  'New password and Confirm password are not same')

        if invalid_req.has_errors:
            return invalid_req

        token = adict['token']

        return ResetPasswordRequestObject(entity_cls, token, adict['data'])


class ResetPasswordUsecase(UseCase):
    """
    This class implements the usecase for resetting password
    """

    def process_request(self, request_object):
        token = request_object.token
        data = request_object.data

        verify_token_use_case = VerifyTokenUseCase()
        verify_token_req_obj = VerifyTokenRequestObject.from_dict(
            request_object.entity_cls, {'token': token})
        response_object = verify_token_use_case.execute(verify_token_req_obj)

        if response_object.success:
            account = response_object.value
            password_check = validate_new_password(
                data['new_password'], account.password_history)
            if password_check['is_valid']:
                password = pbkdf2_sha256.hash(data['new_password'])
                password_history = modify_password_history(
                    account.password, account.password_history)
                account.update(
                    {'password': password,
                     'is_locked': False,
                     'login_attempts': 0,
                     'password_history': password_history})

                return ResponseSuccess(Status.SUCCESS, {"message": "Success"})
            else:
                return ResponseFailure.build_unprocessable_error(
                    {'new_password': password_check['error']})
        else:
            return response_object


class LoginRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for Login
    """

    def __init__(self, entity_cls, username_or_email, password):
        """Initialize Request Object with username/password"""
        self.entity_cls = entity_cls
        self.username_or_email = username_or_email
        self.password = password

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()
        username_or_email = password = None

        if 'username_or_email' not in adict:
            invalid_req.add_error('username_or_email',
                                  'Username or Email is mandatory')
        else:
            username_or_email = adict['username_or_email']

        if 'password' not in adict:
            invalid_req.add_error('password', 'Password is mandatory')
        else:
            password = adict['password']

        if invalid_req.has_errors:
            return invalid_req

        return LoginRequestObject(
            entity_cls, username_or_email, password)


class LoginUseCase(UseCase):
    """This class implements the Authentication Usecase"""

    def process_request(self, request_object):
        """Process Login Request"""
        # FIXME Use `OR` condition for `username` or `email` query
        account = Account.query.filter(
            username=request_object.username_or_email).first
        if not account:
            account = Account.query.filter(
                email=request_object.username_or_email).first
            if not account:
                return ResponseFailure.build_unprocessable_error(
                    {'username_or_email': 'Account does not exist'})

        if not account.is_locked and account.is_active:
            if pbkdf2_sha256.verify(request_object.password, account.password):

                if active_config.ENABLE_ACCOUNT_VERIFICATION and \
                        not account.is_verified:
                    # Todo: Handle sending account verification mail
                    return ResponseFailure.build_unprocessable_error(
                        {'username_or_email': 'Account is not verified'})
                else:
                    # Run the login callback usecase and return its response
                    auth_backend = get_auth_backend()
                    cb_usecase = auth_backend.LoginCallbackUseCase()
                    cb_request_obj = LoginCallbackRequestObject.from_dict(
                        request_object.entity_cls, {'account': account})
                    return cb_usecase.execute(cb_request_obj)
            else:
                allowed_login_attempts = \
                    active_config.PASSWORD_RULES['max_invalid_attempts']
                if account.login_attempts and \
                        account.login_attempts >= allowed_login_attempts:
                    account.update(account.id, {'is_locked': True})
                    return ResponseFailure.build_unprocessable_error(
                        {'password': 'Exceeded maximum invalid attempts. '
                                     'Account has been locked.'})
                else:
                    account.login_attempts += 1
                    account.update({'login_attempts': account.login_attempts})
                    return ResponseFailure.build_unprocessable_error(
                        {'password': 'Password is not correct.'})
        else:
            return ResponseFailure.build_unprocessable_error(
                {'username_or_email': 'Account has been locked/deactivated.'})


class LoginCallbackRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for Login Callback
    """

    def __init__(self, entity_cls, account):
        """Initialize Request Object with the account object"""
        self.entity_cls = entity_cls
        self.account = account

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()

        if 'account' not in adict:
            invalid_req.add_error('account',
                                  'Account object is mandatory')

        if invalid_req.has_errors:
            return invalid_req

        return LoginCallbackRequestObject(entity_cls, adict['account'])


class LogoutRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for Logout
    """

    def __init__(self, entity_cls, account):
        """Initialize Request Object with the account object"""
        self.entity_cls = entity_cls
        self.account = account

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()

        if 'account' not in adict:
            invalid_req.add_error('account',
                                  'Account object is mandatory')

        if invalid_req.has_errors:
            return invalid_req

        return LogoutRequestObject(entity_cls, adict['account'])


class LogoutUseCase(UseCase):
    """This class implements the Authentication Usecase"""

    def process_request(self, request_object):
        """ Process Logout Request """

        # Run the logout callback usecase of the backend and
        # return its response
        auth_backend = get_auth_backend()
        cb_usecase = auth_backend.LogoutCallbackUseCase()
        return cb_usecase.execute(request_object)
