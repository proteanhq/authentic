""" Usecase for handling basic Authentication """
from jwt.algorithms import requires_cryptography
from jwt.exceptions import DecodeError

from protean.core.transport import (InvalidRequestObject, ValidRequestObject)
from protean.core.transport import ResponseSuccess, ResponseFailure, Status
from protean.core.usecase import UseCase
from protean.core.exceptions import ObjectNotFoundError
from protean.conf import active_config

from .tokens import decode_jwt, encode_access_token
from .exceptions import JWTDecodeError


class LoginCallbackUseCase(UseCase):
    """ Default login callback that just returns the account """

    def process_request(self, request_object):
        """Process Login Callback Request"""

        # Build the identity to be encoded in the jwt
        identity = {
            'account_id': request_object.account.id
        }
        if active_config.JWT_IDENTITY_CALLBACK:
            identity.update(request_object.account)

        # Get the encode key for the alg
        encode_key = active_config.SECRET_KEY
        if active_config.JWT_ALGORITHM in requires_cryptography:
            with open(active_config.JWT_PRIVATE_KEY) as fp:
                encode_key = fp.read()

        # Generate the jwt token and return in response
        access_token = encode_access_token(
            identity=identity,
            secret=encode_key,
            algorithm=active_config.JWT_ALGORITHM,
            expires_delta=active_config.JWT_ACCESS_TOKEN_EXPIRES,
            fresh=False,
            csrf=False,
            identity_claim_key=active_config.JWT_IDENTITY_CLAIM,
            user_claims=None,
            user_claims_key=None,
        )
        return ResponseSuccess(Status.SUCCESS, {'access_token': access_token})


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
        elif adict['auth_scheme'].lower() != 'bearer':
            invalid_req.add_error('auth_scheme',
                                  'JWT Backend supports only Bearer Scheme')

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
        # Get the decode key for the alg
        decode_key = active_config.SECRET_KEY
        if active_config.JWT_ALGORITHM in requires_cryptography:
            with open(active_config.JWT_PUBLIC_KEY) as fp:
                decode_key = fp.read()

        # Decode and validate the jwt
        try:
            jwt_data = decode_jwt(
                encoded_token=request_object.credentials,
                secret=decode_key,
                algorithm=active_config.JWT_ALGORITHM,
                identity_claim_key=active_config.JWT_IDENTITY_CLAIM
            )
        except (JWTDecodeError, DecodeError) as e:
            return ResponseFailure.build_unprocessable_error(
                {'credentials': f'Invalid JWT Token. {e}'})

        # Find the identity in the decoded jwt
        identity = jwt_data.get(active_config.JWT_IDENTITY_CLAIM, None)
        try:
            account = self.repo.get(identity['account_id'])
        except ObjectNotFoundError:
            return ResponseFailure.build_unprocessable_error(
                {'username_or_email': 'Account does not exist'})

        return ResponseSuccess(Status.SUCCESS, account)

