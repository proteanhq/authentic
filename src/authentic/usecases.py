"""Usecases for Account CRUD and Authentication Flows"""

import datetime
import uuid
import pyotp
from passlib.hash import pbkdf2_sha256

from protean.core.transport import (InvalidRequestObject, ValidRequestObject)
from protean.core.transport import ResponseSuccess, ResponseSuccessCreated,\
    ResponseFailure, Status
from protean.core.usecase import (UseCase, ShowRequestObject,
                                  UpdateRequestObject, UpdateUseCase)
from protean.context import context
from protean.conf import active_config

from authentic.helper import validate_new_password, modify_password_history


class RegisterRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for self registration
    """

    def __init__(self, entity_cls, data=None):
        """Initialize Request Object with form data"""
        self.entity_cls = entity_cls
        self.data = data

    @classmethod
    def from_dict(cls, entity_cls, adict):
        """Create Request Object from dict"""
        invalid_req = InvalidRequestObject()

        if 'email' not in adict:
            invalid_req.add_error('email', 'Email is mandatory')
        elif 'username' not in adict:
            adict['username'] = adict['email'].split('@')[0]
        if 'password' not in adict:
            invalid_req.add_error('password', 'Password is mandatory')

        if invalid_req.has_errors:
            return invalid_req

        return RegisterRequestObject(entity_cls, adict)


class RegisterUseCase(UseCase):
    """
    This class implements the usecase for registering candidate
    """

    def process_request(self, request_object):
        """Process Create Account Request"""
        data = request_object.data

        if self.repo.filter(email=data['email']):
            return ResponseFailure.build_unprocessable_error(
                {'email': 'Email already exists'})

        if self.repo.filter(username=data['username']):
            return ResponseFailure.build_unprocessable_error(
                {'username': 'Username already exists'})

        password_check = validate_new_password(data['password'], [])
        if not password_check['is_valid']:
            return ResponseFailure.build_unprocessable_error(
                {'password': password_check['error']})

        data['password'] = pbkdf2_sha256.hash(data['password'])
        account = self.repo.create(data)
        return ResponseSuccessCreated(account)


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

        if 'roles' in adict:
            if not set(adict['roles']).issubset(active_config.ROLES):
                invalid_req.add_error('roles', 'Invalid role(s)')

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

        if self.repo.filter(email=data['email']):
            return ResponseFailure.build_unprocessable_error(
                {'email': 'Email already exists'})

        if not is_idp_login:
            if self.repo.filter(username=data['username']):
                return ResponseFailure.build_unprocessable_error(
                    {'username': 'Username already exists'})

            password_check = validate_new_password(data['password'], [])
            if not password_check['is_valid']:
                return ResponseFailure.build_unprocessable_error(
                    {'password': password_check['error']})

        data['password'] = pbkdf2_sha256.hash(data['password'])
        account = self.repo.create(data)

        return ResponseSuccessCreated(account)


class UpdateAccountRequestObject(UpdateRequestObject):
    """
    This class encapsulates the Request Object for Updating Account
    """

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()
        if 'roles' in adict:
            if not set(adict['roles']).issubset(active_config.ROLES):
                invalid_req.add_error('roles', 'Invalid role(s)')

        if invalid_req.has_errors:
            return invalid_req

        return super().from_dict(entity_cls, adict)


class UpdateAccountUseCase(UpdateUseCase):
    """
    This class implements the usecase for updating Account
    """

    def process_request(self, request_object):
        """Process update Account Request"""
        account_obj = self.repo.get(request_object.identifier)
        if request_object.data.get('email') and \
                account_obj.email != request_object.data.get('email') and \
                self.repo.filter(email=request_object.data['email']):
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

    def __init__(self, identifier=None, data=None):
        """Initialize Request Object with form data"""
        self.data = data
        self.identifier = identifier

    @classmethod
    def from_dict(cls, adict):
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
        if new_password and confirm_password and \
                new_password != confirm_password:
            invalid_req.add_error('confirm_password',
                                  'Password and Confirm password must be same')

        if invalid_req.has_errors():
            return invalid_req

        identifier = adict['identifier']

        return ChangeAccountPasswordRequestObject(identifier, adict['data'])


class ChangeAccountPasswordUseCase(UseCase):
    """
    This class implements the usecase for updating Account
    """

    def process_request(self, request_object):
        """Process update Account Request"""

        identifier = request_object.identifier
        data = request_object.data
        account = self.repo.get(identifier)

        if pbkdf2_sha256.verify(data['current_password'], account.password):
            password_check = validate_new_password(
                self.repo_factory.get_repo('tenant'),
                data['new_password'],
                account.password_history)
            if password_check['is_valid']:
                password = pbkdf2_sha256.hash(data['new_password'])
                password_history = modify_password_history(
                    self.repo_factory.get_repo('tenant'),
                    account.password,
                    account.password_history)
                self.repo.update(
                    request_object.identifier,
                    {'password': password,
                     'password_history': password_history})
                return ResponseSuccess({"message": "Success"})
            else:
                return ResponseFailure.build_unprocessable_error(
                    {'password': password_check['error']})
        else:
            return ResponseFailure.build_unprocessable_error(
                {'password': 'Invalid Password'})


class SendResetPasswordEmailRequestObject(ValidRequestObject):
    """
    This class implements the request object for sending reset password email
    """

    def __init__(self, email=None, host_url=None):
        self.email = email
        self.host_url = host_url

    @classmethod
    def from_dict(cls, adict):
        invalid_req = InvalidRequestObject()
        if 'email' in adict:
            email = adict['email']
        else:
            invalid_req.add_error('email', 'Email is mandatory')

        if 'host_url' in adict:
            host_url = adict['host_url']
        else:
            invalid_req.add_error('host_url', 'Host URL is mandatory')

        if invalid_req.has_errors():
            return invalid_req

        return SendResetPasswordEmailRequestObject(email, host_url)


class SendResetPasswordEmailUsecase(UseCase):
    """
    This class implements the usecase for sending reset password email
    """

    def process_request(self, request_object):
        email = request_object.email
        account = self.repo.find_by(('email', email))

        if account:
            token = str(uuid.uuid4())

            reset_link = "{}reset_password/{}".format(request_object.host_url,
                                                      token)
            self.repo.update(
                account.id,
                {
                    "verification_token": token,
                    "token_timestamp": datetime.datetime.now() + datetime.timedelta(
                        hours=24)})

            payload = {
                "email": email,
                "subject": "Reset Password Request",
                "reset_link": reset_link
            }

            # EmailHelper.send_email(
            #     payload,
            #     getattr(active_config, 'RESET_PASSWORD_MAIL_TEMPLATE', None))

        return ResponseSuccess({"message": "Success"})


class VerifyTokenRequestObject(ValidRequestObject):
    """
    This class implements the request object for resetting password
    """

    def __init__(self, token=None):
        self.token = token

    @classmethod
    def from_dict(cls, adict):
        invalid_req = InvalidRequestObject()

        if 'token' not in adict:
            invalid_req.add_error('token', 'Token is mandatory')

        if invalid_req.has_errors():
            return invalid_req

        token = adict['token']

        return VerifyTokenRequestObject(token)


class VerifyTokenUseCase(UseCase):
    """
    This class implements the usecase for verifying token
    """

    def process_request(self, request_object):
        token = request_object.token
        account = self.repo.find_by(('verification_token', token))

        if account:
            token_time = datetime.datetime.strptime(account.token_timestamp,
                                                    "%Y-%m-%dT%H:%M:%S.%f")
            if datetime.datetime.now() > token_time:
                return ResponseFailure.build_unprocessable_error(
                    "Token expired")
            else:
                self.repo.update(account.id, {"is_verified": True})
                return ResponseSuccess({"message": "Valid Token"})
        else:
            return ResponseFailure.build_unprocessable_error("Invalid Token")


class ResetPasswordRequestObject(ValidRequestObject):
    """
    This class implements the request object for resetting password
    """

    def __init__(self, token=None, data=None):
        self.data = data
        self.token = token

    @classmethod
    def from_dict(cls, adict):
        invalid_req = InvalidRequestObject()

        data = adict['data']

        if 'token' not in adict:
            invalid_req.add_error('token', 'Token is mandatory')
        new_password = data.get('new_password')
        if new_password is None:
            invalid_req.add_error('new_password', 'New password is mandatory')
        confirm_password = data.get('confirm_password')
        if confirm_password is None:
            invalid_req.add_error('confirm_password',
                                  'Confirm password is mandatory')
        if new_password and confirm_password and new_password != confirm_password:
            invalid_req.add_error('new_password',
                                  'New password and Confirm password are not same')

        if invalid_req.has_errors():
            return invalid_req

        token = adict['token']

        return ResetPasswordRequestObject(token, adict['data'])


class ResetPasswordUsecase(UseCase):
    """
    This class implements the usecase for resetting password
    """

    def process_request(self, request_object):
        token = request_object.token
        data = request_object.data
        account = self.repo.find_by(('verification_token', token))

        verify_token_use_case = VerifyTokenUseCase(self.repo_factory)
        obj = VerifyTokenRequestObject.from_dict({
            'token': token
        })
        response_object = verify_token_use_case.execute(obj)

        if bool(response_object):
            password_check = validate_new_password(
                self.repo_factory.get_repo('tenant'),
                data['new_password'],
                account.password_history)
            if password_check['is_valid']:
                password = pbkdf2_sha256.hash(data['new_password'])
                password_history = modify_password_history(
                    self.repo_factory.get_repo('tenant'),
                    account.password,
                    account.password_history)
                self.repo.update(
                    account.id, {'password': password,
                                 'is_locked': False,
                                 'login_attempts': 0,
                                 'password_history': password_history})

                return ResponseSuccess({"message": "Success"})
            else:
                return ResponseFailure.build_unprocessable_error(
                    {'password': password_check['error']})
        else:
            return response_object


class AuthenticateRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for Authentication
    """

    def __init__(self, username_or_email, password):
        """Initialize Request Object with username/password"""
        self.username_or_email = username_or_email
        self.password = password

    @classmethod
    def from_dict(cls, adict):
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

        if invalid_req.has_errors():
            return invalid_req

        return AuthenticateRequestObject(username_or_email, password)


class AuthenticateUseCase(UseCase):
    """This class implements the Authentication Usecase"""

    def process_request(self, request_object):
        """Process Authentication Request"""
        account = self.repo.find_by([
            ('username.raw', request_object.username_or_email),
            ('tenant_id', context.tenant_id)
        ], True)
        if not account:
            account = self.repo.find_by([
                ('email', request_object.username_or_email),
                ('tenant_id', context.tenant_id)
            ], True)
            if not account:
                return False, 401

        if not account.is_locked:
            if ResponseSuccess(
                pbkdf2_sha256.verify(request_object.password, account.password)) \
                .value:
                if account.is_verified:
                    return account, 200

                send_account_verification_link = SendAccountVerificationLinkUseCase(
                    self.repo)
                send_account_verification_link.execute({
                    "account": account
                })
                return ResponseFailure.build_unprocessable_error(
                    {'account': 'Account is not verified'})
            else:
                tenant_repo = self.repo_factory.get_repo('tenant')
                allowed_login_attempts = \
                tenant_repo.get(account.tenant_id, True) \
                    .password_rules['max_invalid_attempts']
                login_attempts = account.__dict__.get('login_attempts', None)
                if login_attempts and login_attempts >= allowed_login_attempts:
                    self.repo.update(account.id, {'is_locked': True})
                    return False, 422
                else:
                    login_attempts = (login_attempts or 0) + 1
                    self.repo.update(account.id,
                                     {'login_attempts': login_attempts})
                    return False, 401
        else:
            return False, 422


class SendAccountVerificationLinkUseCase(UseCase):
    """Send account verification link"""

    def process_request(self, request_object):
        account = request_object['account']
        token = str(uuid.uuid4())

        verification_link = "{}account_verification/{}".format(
            request_object['host_url'], token)
        self.repo.update(
            account.id,
            {"verification_token": token,
             "token_timestamp": datetime.datetime.now() + datetime.timedelta(
                 hours=24)})

        subject = "Almost there.. Verify email now!"

        if account.email:
            payload = {
                "email": account.email,
                "subject": subject,
                "verification_link": verification_link
            }

            # EmailHelper.send_email(
            #     payload,
            #     getattr(active_config, 'VERIFICATION_MAIL_TEMPLATE', None))

        elif account.phone:
            payload = {
                "to": account.phone,
                "body": verification_link
            }
            # Sms.send_sms(payload)

        return ResponseSuccess({"message": "Verification link sent"})


class GenerateMfaUriForQrCodeRequestObject(ShowRequestObject):
    """
    This class implements the request object for Mfa Url
    """


class GenerateMfaUriForQrCodeUseCase(UseCase):
    """This class implements the usecase for Mfa Url"""

    def process_request(self, request_object):
        identifier = request_object.identifier
        account = self.repo.get(identifier, True)

        # Generate and store MFA key for the account
        mfa_key = pyotp.random_base32()
        self.repo.update(identifier, {"mfa_key": mfa_key})

        # Base64 encode using account key and common key
        # Restrict to 16 characters - MFA supports keys with 16 length only
        # FIXME MFA throws invalid secret key with following approach
        # secret = base64.b64encode(bytes(mfa_key + CONFIG.MFA_SECRET_KEY,
        #                                 encoding='utf-8')).decode('utf-8')[:16]
        uri = pyotp.totp.TOTP(mfa_key).provisioning_uri(
            account.email,
            issuer_name=getattr(active_config, 'ISSUER', None))
        return ResponseSuccess(uri)


class VerifyMfaOtpRequestObject(ValidRequestObject):
    """
    This class implements the request object for mfa verification
    """

    def __init__(self, identifier=None, mfa_otp=None):
        """Initialize Request Object with form data"""
        self.identifier = identifier
        self.mfa_otp = mfa_otp

    @classmethod
    def from_dict(cls, adict):
        invalid_req = InvalidRequestObject()

        if 'identifier' not in adict:
            invalid_req.add_error('identifier', 'identifier is mandatory')

        if 'mfa_otp' not in adict:
            invalid_req.add_error('mfa_otp', 'mfa_otp is mandatory')

        if invalid_req.has_errors():
            return invalid_req

        identifier = adict['identifier']
        mfa_otp = adict['mfa_otp']

        return VerifyMfaOtpRequestObject(identifier, mfa_otp)


class VerifyMfaOtpUseCase(UseCase):
    """This class implements the usecase for Mfa verification"""

    def process_request(self, request_object):
        identifier = request_object.identifier
        mfa_otp = request_object.mfa_otp
        account = self.repo.get(identifier)
        # FIXME MFA throws invalid key with the following approach
        # secret = base64.b64encode(bytes(account.mfa_key + CONFIG.MFA_SECRET_KEY,
        #                                 encoding='utf-8')).decode('utf-8')[:16]
        totp = pyotp.TOTP(account.mfa_key)
        if not totp.verify(mfa_otp):
            return ResponseFailure.build_unprocessable_error(
                "Invalid OTP")
        if not account.mfa_enabled:
            self.repo.update(identifier, {
                "mfa_enabled": True
            })

        return ResponseSuccess({"message": "Valid OTP"})



