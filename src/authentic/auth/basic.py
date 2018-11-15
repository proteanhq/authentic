""" Usecase for handling basic Authentication """
from protean.core.transport import (InvalidRequestObject, ValidRequestObject)
from protean.core.transport import ResponseSuccess, ResponseSuccessCreated,\
    ResponseFailure, Status
from protean.core.usecase import UseCase
from protean.conf import active_config


class LoginCallbackUseCase(UseCase):
    """ Default login callback that just returns the account """

    def process_request(self, request_object):
        """Process Login Callback Request"""
        return ResponseSuccess(Status.SUCCESS, request_object.account)


class AuthenticationRequestObject(ValidRequestObject):
    """"""


class AuthenticationUseCase(UseCase):
    """"""

