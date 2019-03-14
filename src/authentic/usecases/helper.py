""" Helper usecases defining common reusable functionality  """
import datetime

from protean.core.transport import InvalidRequestObject
from protean.core.transport import ResponseFailure
from protean.core.transport import ResponseSuccess
from protean.core.transport import Status
from protean.core.transport import ValidRequestObject
from protean.core.usecase import UseCase

from ..utils import get_account_entity


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
        account = get_account_entity().query.filter(
            verification_token=token).first

        if account:
            token_time = account.token_timestamp
            if datetime.datetime.utcnow() > token_time:
                return ResponseFailure.build_unprocessable_error(
                    "Token expired")
            else:
                account.update({"is_verified": True})
                return ResponseSuccess(Status.SUCCESS, account)
        else:
            return ResponseFailure.build_unprocessable_error("Invalid Token")
