""" Helper usecases defining common reusable functionality  """
import datetime

from protean.core.transport import (InvalidRequestObject, ValidRequestObject)
from protean.core.transport import ResponseSuccess, ResponseFailure, Status
from protean.core.usecase import (UseCase, )


class VerifyTokenRequestObject(ValidRequestObject):
    """
    This class implements the request object for resetting password
    """

    def __init__(self, entity_cls, token=None):
        self.entity_cls = entity_cls
        self.token = token

    @classmethod
    def from_dict(cls, entity_cls, adict):
        invalid_req = InvalidRequestObject()

        if 'token' not in adict:
            invalid_req.add_error('token', 'Token is mandatory')

        if invalid_req.has_errors:
            return invalid_req

        token = adict['token']

        return VerifyTokenRequestObject(entity_cls, token)


class VerifyTokenUseCase(UseCase):
    """
    This class implements the usecase for verifying token
    """

    def process_request(self, request_object):
        token = request_object.token
        account = self.repo.filter(verification_token=token).first

        if account:
            token_time = account.token_timestamp
            if datetime.datetime.utcnow() > token_time:
                return ResponseFailure.build_unprocessable_error(
                    "Token expired")
            else:
                self.repo.update(account.id, {"is_verified": True})
                return ResponseSuccess(Status.SUCCESS, account)
        else:
            return ResponseFailure.build_unprocessable_error("Invalid Token")
