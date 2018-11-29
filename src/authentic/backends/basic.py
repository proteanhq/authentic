""" Usecase for handling basic Authentication """
import base64
import binascii

from protean.core.transport import (InvalidRequestObject, ValidRequestObject)
from protean.core.transport import ResponseSuccess, ResponseFailure, Status
from protean.core.usecase import UseCase

from authentic.usecases import LoginRequestObject, LoginUseCase


class LoginCallbackUseCase(UseCase):
    """ Login callback that just returns the account """

    def process_request(self, request_object):
        """Process Login Callback Request"""
        return ResponseSuccess(Status.SUCCESS, request_object.account)


class AuthenticationRequestObject(ValidRequestObject):
    """
    This class encapsulates the Request Object for Basic Authentication
    """

    def __init__(self, entity_cls, credentials):
        """Initialize Request Object with the auth scheme and credentials"""
        self.entity_cls = entity_cls
        self.credentials = credentials

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()

        if 'auth_scheme' not in adict:
            invalid_req.add_error('auth_scheme',
                                  'Authentication scheme is mandatory')
        elif adict['auth_scheme'].lower() != 'basic':
            invalid_req.add_error('auth_scheme',
                                  'Basic Backend supports only Basic Scheme')

        if 'credentials' not in adict:
            invalid_req.add_error('credentials', 'Credentials is mandatory')

        if invalid_req.has_errors:
            return invalid_req

        return AuthenticationRequestObject(entity_cls, adict['credentials'])


class AuthenticationUseCase(UseCase):
    """
    This class encapsulates the Use Case for Basic Authentication
    """

    def process_request(self, request_object):
        """Process Authentication Request"""

        try:
            auth_parts = base64.b64decode(
                request_object.credentials).decode('iso-8859-1').partition(':')
        except (TypeError, UnicodeDecodeError, binascii.Error):
            return ResponseFailure.build_unprocessable_error(
                {'credentials': 'Invalid basic header. Credentials not '
                                'correctly base64 encoded.'})

        payload = {
            'username_or_email': auth_parts[0],
            'password': auth_parts[2],
        }

        request_object = LoginRequestObject.from_dict(
            request_object.entity_cls, payload)
        use_case = LoginUseCase(self.repo)
        return use_case.execute(request_object)


class LogoutCallbackUseCase(UseCase):
    """ Logout callback that just returns success """

    def process_request(self, request_object):
        """ Process Logout Callback Request """
        return ResponseSuccess(Status.SUCCESS, {'message': 'success'})
