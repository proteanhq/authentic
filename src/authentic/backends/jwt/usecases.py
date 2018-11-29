""" Usecase for handling basic Authentication """
from datetime import datetime

from jwt.algorithms import requires_cryptography
from jwt.exceptions import DecodeError

from protean.core.transport import (InvalidRequestObject, ValidRequestObject,
                                    Status)
from protean.core.transport import ResponseSuccess, ResponseFailure, Status
from protean.core.usecase import UseCase
from protean.core.exceptions import ObjectNotFoundError
from protean.core.repository import repo
from protean.conf import active_config
from protean.context import context

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
        token_data, access_token = encode_access_token(
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

        # Save the session to enable logout
        repo.SessionSchema.create(
            session_key=f'token-{request_object.account.id}'
                        f'-{token_data["jti"]}',
            session_data={},
            expire_date=datetime.utcnow() +
                        active_config.JWT_ACCESS_TOKEN_EXPIRES
        )
        context.set_context({'jwt_data': token_data})
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
            return ResponseFailure(
                Status.UNAUTHORIZED, {'credentials': f'Invalid JWT Token. {e}'})

        # Find the identity in the decoded jwt
        identity = jwt_data.get(active_config.JWT_IDENTITY_CLAIM, None)
        try:
            account = self.repo.get(identity['account_id'])
        except ObjectNotFoundError:
            return ResponseFailure(
                Status.UNAUTHORIZED,
                {'username_or_email': 'Account does not exist'})

        # Make sure that the session exits
        session = repo.SessionSchema.filter(
            session_key=f'token-{account.id}-{jwt_data["jti"]}',
        )
        if not session or session.first.expire_date < datetime.utcnow():
            return ResponseFailure(
                Status.UNAUTHORIZED, {'token': 'Invalid Token'})

        context.set_context({'jwt_data': jwt_data})
        return ResponseSuccess(Status.SUCCESS, account)


class LogoutCallbackUseCase(UseCase):
    """ Logout callback that just returns success """

    def process_request(self, request_object):
        """ Process Logout Callback Request """
        # Remove the session
        repo.SessionSchema.delete(
            f'token-{request_object.account.id}-{context.jwt_data["jti"]}')
        return ResponseSuccess(Status.SUCCESS, {'message': 'success'})
