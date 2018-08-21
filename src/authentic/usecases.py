"""Usecases for Account CRUD and Authentication Flows"""

import datetime
import uuid
import pyotp
from passlib.hash import pbkdf2_sha256

from protean.integrations.email import EmailHelper
from protean.core.transport import (InvalidRequestObject, ValidRequestObject)
from protean.core.transport import ResponseSuccess, ResponseFailure
from protean.integrations.sms import Sms
from protean.core.usecase import (UseCase, ShowRequestObject)
from protean.context import context
from protean.conf import active_config

from authentic.entities import Account, ROLES
from authentic.helper import PasswordHandler


class RegisterRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for self registration
    """

    def __init__(self, data=None):
        """Initialize Request Object with form data"""
        self.data = data

    @classmethod
    def from_dict(cls, adict):
        """Create Request Object from dict"""
        invalid_req = InvalidRequestObject()

        if 'email' not in adict:
            invalid_req.add_error('email', 'Email is mandatory')
        elif 'username' not in adict:
            adict['username'] = adict['email'].split('@')[0]
        if 'password' not in adict:
            invalid_req.add_error('password', 'Password is mandatory')

        if invalid_req.has_errors():
            return invalid_req

        return RegisterRequestObject(adict)


class RegisterUseCase(UseCase):
    """
    This class implements the usecase for registering candidate
    """

    def process_request(self, request_object):
        """Process Create Account Request"""
        data = request_object.data

        if self.repo.find_by(('email', data['email'])):
            return ResponseFailure.build_unprocessable_error({'email': 'Email already exists'})

        if self.repo.find_by(('username', data['username'])):
            return ResponseFailure.build_unprocessable_error(
                {'username': 'Username already exists'})

        password_check = validate_new_password(
            self.repo_factory.get_repo('tenant'),
            data['password'], [])
        if not password_check['is_valid']:
            return ResponseFailure.build_unprocessable_error({'password': password_check['error']})

        account = Account(username=data['username'],
                          password=pbkdf2_sha256.hash(data['password']),
                          name=data.get('name', ''),
                          roles=data.get('roles', ''),
                          email=data.get('email', ''),
                          phone=data.get('phone', ''),
                          tenant_id=context.tenant_id,
                          is_verified=False,
                          created_at=datetime.datetime.now(),
                          updated_at=datetime.datetime.now())

        account = self.repo.create(account)

        if account:
            send_account_verfication_link = SendAccountVerificationLinkUseCase(self.repo_factory)
            send_account_verfication_link.execute({
                "account": account,
                "host_url": data.get('host_url')
            })

        return ResponseSuccess(account)


class CreateAccountRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for Creating Accounts
    """

    def __init__(self, data=None):
        """Initialize Request Object with form data"""
        self.data = data

    @classmethod
    def from_dict(cls, adict):
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
                invalid_req.add_error('confirm_password', 'Confirm password is mandatory')
            else:
                if adict['password'] != adict['confirm_password']:
                    invalid_req.add_error(
                        'confirm_password',
                        'Password and Confirm password must be same')
                else:
                    del adict['confirm_password']
            if 'phone' not in adict:
                invalid_req.add_error('phone', 'Phone is mandatory')

        if 'roles' in adict:
            if isinstance(adict['roles'], str):
                if adict['roles'] not in ROLES:
                    invalid_req.add_error('roles', 'Invalid role(s)')

            if isinstance(adict['roles'], list):
                if not set(adict['roles']).issubset(ROLES):
                    invalid_req.add_error('roles', 'Invalid role(s)')

        if invalid_req.has_errors():
            return invalid_req

        return CreateAccountRequestObject(adict)


class CreateAccountUseCase(UseCase):
    """
    This class implements the usecase for creating an Account
    """

    def process_request(self, request_object):
        """Process Create Account Request"""
        data = request_object.data
        is_idp_login = request_object.data.get('is_idp', False)

        if self.repo.find_by(('email', data['email'])):
            return ResponseFailure.build_unprocessable_error({'email': 'Email already exists'})

        if not is_idp_login:
            if self.repo.find_by(('username', data['username'])):
                return ResponseFailure.build_unprocessable_error(
                    {'username': 'Username already exists'})

            password_check = validate_new_password(
                self.repo_factory.get_repo('tenant'),
                data['password'], [])
            if not password_check['is_valid']:
                return ResponseFailure.build_unprocessable_error(
                    {'password': password_check['error']})

        account = Account(
            username=data.get('username', ''),
            password=pbkdf2_sha256.hash(data.get('password', '')),
            name=data.get('name', ''),
            title=data.get('title', ''),
            roles=data.get('roles', ''),
            location=data.get('location', None),
            email=data.get('email', ''),
            phone=data.get('phone', ''),
            is_idp=data.get('is_idp', False),
            is_verified=True,
            created_by=data.get('user_id'),
            updated_by=data.get('user_id'),
            created_at=datetime.datetime.now(),
            updated_at=datetime.datetime.now(),
            customer_id=data.get('customer_id'),
            timezone=data.get('timezone', '')
        )
        account = self.repo.create(account)

        return ResponseSuccess(account)


class UpdateAccountRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for Updating Account
    """

    def __init__(self, cls_entity, identifier=None, data=None):
        """Initialize Request Object with form data"""
        self.cls_entity = cls_entity
        self.data = data
        self.identifier = identifier

    @classmethod
    def from_dict(cls, cls_entity, adict):
        invalid_req = InvalidRequestObject()

        if 'identifier' not in adict:
            invalid_req.add_error('identifier', 'ID is mandatory')
        if 'data' not in adict:
            invalid_req.add_error('data', 'Payload is mandatory')
        else:
            data = adict['data']
            if 'password' in data:
                if 'confirm_password' not in data:
                    invalid_req.add_error('confirm_password', 'Confirm password is mandatory')
                else:
                    if data['password'] != data['confirm_password']:
                        invalid_req.add_error('confirm_password',
                                              'Password and Confirm password must be same')
                    else:
                        del data['confirm_password']

        if invalid_req.has_errors():
            return invalid_req

        identifier = adict['identifier']
        data['updated_at'] = datetime.datetime.now()
        data['updated_by'] = adict['current_user']

        return UpdateAccountRequestObject(cls_entity, identifier, data)


class UpdateAccountUseCase(UseCase):
    """
    This class implements the usecase for updating Account
    """

    def process_request(self, request_object):
        """Process update Account Request"""
        account_obj = self.repo.get(request_object.identifier)
        if (request_object.data.get('email') and
                account_obj.email != request_object.data.get('email') and
                self.repo.find_by(('email', request_object.data['email']))):
            return ResponseFailure.build_unprocessable_error(
                {'email': 'Email already exists'})

        if (request_object.data.get('username') and
                account_obj.username != request_object.data.get('username')
                and self.repo.find_by(('username', request_object.data['username']))):
            return ResponseFailure.build_unprocessable_error(
                {'username': 'Username already exists'})

        if 'password' in request_object.data:
            password_check = validate_new_password(
                self.repo_factory.get_repo('tenant'),
                request_object.data['password'],
                account_obj.password_history)

            if password_check['is_valid']:
                request_object.data['password'] = pbkdf2_sha256.hash(
                    request_object.data['password'])
                password_history = modify_password_history(
                    self.repo_factory.get_repo('tenant'),
                    account_obj.password,
                    account_obj.password_history)
                request_object.data['password_history'] = password_history
            else:
                return ResponseFailure.build_unprocessable_error(
                    {'password': password_check['error']})

        account_obj = self.repo.update(
            request_object.identifier, request_object.data)
        return ResponseSuccess(account_obj)


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
            invalid_req.add_error('current_password', 'Current password is mandatory')
        new_password = data.get('new_password')
        if new_password is None:
            invalid_req.add_error('new_password', 'New password is mandatory')
        confirm_password = data.get('confirm_password')
        if new_password and confirm_password and new_password != confirm_password:
            invalid_req.add_error('confirm_password', 'Password and Confirm password must be same')

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
                    {'password': password, 'password_history': password_history})
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

            reset_link = "{}reset_password/{}".format(request_object.host_url, token)
            self.repo.update(
                account.id,
                {
                    "verification_token": token,
                    "token_timestamp": datetime.datetime.now() + datetime.timedelta(hours=24)})

            payload = {
                "email": email,
                "subject": "Reset Password Request",
                "reset_link": reset_link
            }

            EmailHelper.send_email(
                payload,
                getattr(active_config, 'RESET_PASSWORD_MAIL_TEMPLATE', None))

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
                return ResponseFailure.build_unprocessable_error("Token expired")
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
            invalid_req.add_error('confirm_password', 'Confirm password is mandatory')
        if new_password and confirm_password and new_password != confirm_password:
            invalid_req.add_error('new_password', 'New password and Confirm password are not same')

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
            invalid_req.add_error('username_or_email', 'Username or Email is mandatory')
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
            if ResponseSuccess(pbkdf2_sha256.verify(request_object.password, account.password)) \
                    .value:
                if account.is_verified:
                    return account, 200

                send_account_verification_link = SendAccountVerificationLinkUseCase(self.repo)
                send_account_verification_link.execute({
                    "account": account
                })
                return ResponseFailure.build_unprocessable_error(
                    {'account': 'Account is not verified'})
            else:
                tenant_repo = self.repo_factory.get_repo('tenant')
                allowed_login_attempts = tenant_repo.get(account.tenant_id, True) \
                    .password_rules['max_invalid_attempts']
                login_attempts = account.__dict__.get('login_attempts', None)
                if login_attempts and login_attempts >= allowed_login_attempts:
                    self.repo.update(account.id, {'is_locked': True})
                    return False, 422
                else:
                    login_attempts = (login_attempts or 0) + 1
                    self.repo.update(account.id, {'login_attempts': login_attempts})
                    return False, 401
        else:
            return False, 422


class SendAccountVerificationLinkUseCase(UseCase):
    """Send account verification link"""

    def process_request(self, request_object):
        account = request_object['account']
        token = str(uuid.uuid4())

        verification_link = "{}account_verification/{}".format(request_object['host_url'], token)
        self.repo.update(
            account.id,
            {"verification_token": token,
             "token_timestamp": datetime.datetime.now() + datetime.timedelta(hours=24)})

        subject = "Almost there.. Verify email now!"

        if account.email:
            payload = {
                "email": account.email,
                "subject": subject,
                "verification_link": verification_link
            }

            EmailHelper.send_email(
                payload,
                getattr(active_config, 'VERIFICATION_MAIL_TEMPLATE', None))

        elif account.phone:
            payload = {
                "to": account.phone,
                "body": verification_link
            }
            Sms.send_sms(payload)

        return ResponseSuccess({"message": "Verification link sent"})


class ValidateAccountRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for Validate Account
    """

    def __init__(self, key, value):
        """Initialize Request Object with parameters"""
        self.key = key
        self.value = value

    @classmethod
    def from_dict(cls, adict):
        invalid_req = InvalidRequestObject()

        if 'key' not in adict:
            invalid_req.add_error('key', 'Key is mandatory')
        else:
            key = adict.get('key')

        if 'value' not in adict:
            invalid_req.add_error('value', 'Value is mandatory')
        else:
            value = adict.get('value')

        if invalid_req.has_errors():
            return invalid_req

        return ValidateAccountRequestObject(key, value)


class ValidateAccountUseCase(UseCase):
    """
    This class implements the usecase for validate account email and username uniqueness
    """

    def process_request(self, request_object):
        if self.repo.find_by(
                (request_object.key, request_object.value)):
            return ResponseSuccess(
                {'message': '%s already exists.' % request_object.key})
        return ResponseFailure.build_not_found(
            {'message': '%s not found' % request_object.key})


class GenerateTempTokenRequestObject(ValidRequestObject):
    """
    This class implements the usecase for generating temp token
    """

    def __init__(self, identifier=None):
        """Initialize Request Object with form data"""
        self.identifier = identifier

    @classmethod
    def from_dict(cls, adict):
        invalid_req = InvalidRequestObject()

        if 'identifier' not in adict:
            invalid_req.add_error('identifier', 'ID is mandatory')

        if invalid_req.has_errors():
            return invalid_req

        identifier = adict['identifier']

        return GenerateTempTokenRequestObject(identifier)


class GenerateTemporaryTokenUseCase(UseCase):
    """Generate temporary token"""

    def process_request(self, request_object):
        identifier = request_object.identifier
        account = self.repo.get(identifier)

        token = str(uuid.uuid4())

        self.repo.update(
            account.id,
            {"temp_token": token,
             "temp_token_timestamp": datetime.datetime.now() + datetime.timedelta(hours=1)})

        return ResponseSuccess({"temp_token": token})


class VerifyTempTokenUseCase(UseCase):
    """
    This class implements the usecase for verifying token
    """

    def process_request(self, request_object):
        token = request_object['token']
        account = self.repo.find_by(('temp_token', token))

        if account:
            token_time = datetime.datetime.strptime(account.temp_token_timestamp,
                                                    "%Y-%m-%dT%H:%M:%S.%f")
            if datetime.datetime.now() > token_time:
                return ResponseFailure.build_unprocessable_error("Token expired")

            return ResponseSuccess({"message": "Valid Token"})

        return ResponseFailure.build_unprocessable_error("Invalid Token")


class GetAccountTenantRequestObject(ValidRequestObject):
    """
    This class implements the request object for Account Tenant usecase
    """

    def __init__(self, username_or_email=None):
        """Initialize Request Object with form data"""
        self.username_or_email = username_or_email

    @classmethod
    def from_dict(cls, adict):
        invalid_req = InvalidRequestObject()

        if 'username_or_email' not in adict:
            invalid_req.add_error('username or email', 'username or email is mandatory')

        if invalid_req.has_errors():
            return invalid_req

        username_or_email = adict['username_or_email']

        return GetAccountTenantRequestObject(username_or_email)


class GetAccountTenantUseCase(UseCase):
    """Get tenant details of account"""

    def process_request(self, request_object):
        username_or_email = request_object.username_or_email
        query = {
            "query": {
                "multi_match": {
                    "query": username_or_email,
                    "fields": ["email", "username"]
                }
            }
        }
        result = self.repo.search_query(page=1, query=query)
        if result['total'] > 0:
            account = result['data'][0]
            tenant_ids = account.tenant_id
            if not isinstance(tenant_ids, list):
                tenant_ids = [str(tenant_ids)]

            tenant_repo = self.repo_factory.get_repo('tenant')
            tenant_list = []
            for tenant_id in tenant_ids:
                tenant = tenant_repo.get(str(tenant_id), True)
                tenant_list.append({"id": tenant_id, "name": tenant.name})

            return ResponseSuccess(tenant_list)
        else:
            return ResponseFailure.build_unprocessable_error(
                "No account found by this username or email")


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


def validate_new_password(repo_factory, new_password, old_password_list):
    """Validate New Password"""

    password_config = repo_factory.repo.get(context.tenant_id, True).password_rules
    password_handler = PasswordHandler(password_config)
    response = password_handler.is_valid(new_password, old_password_list)
    if response['message'] == 'Valid password':
        response['is_valid'] = True
    else:
        response['is_valid'] = False

    return response


def modify_password_history(repo_factory, old_password, input_password_history):
    """Tweak Password History"""

    password_history = input_password_history[:]
    password_config = repo_factory.repo.get(context.tenant_id, True).password_rules
    extra_count = len(password_history) - password_config['min_topology_changes']
    if extra_count >= 0:
        for _ in range(extra_count + 1):
            password_history.pop(0)
    password_history.append(old_password)

    return password_history
