"""Usecases for supporting Multi Factor Authentication """
import pyotp

from protean.core.transport import (InvalidRequestObject, ValidRequestObject)
from protean.core.transport import ResponseSuccess, ResponseFailure
from protean.core.usecase import (UseCase, ShowRequestObject)
from protean.conf import active_config


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
