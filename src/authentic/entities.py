"""Account and Authentication Entities"""
from enum import Enum
from protean.core.entity import Entity
from protean.core import field

from .utils import get_account_roles


class DefaultRolesEnum(Enum):
    """ Enumerator of roles for an account """
    ADMIN = 'ADMIN'


class Account(Entity):
    """
    This class initializes an Account Entity.
    """
    # username, email and password for auth
    username = field.StringMedium(required=True, unique=True)
    email = field.StringLong(required=True, unique=True)
    password = field.StringLong(required=True)

    # List of roles for the Account
    roles = field.List(choices=get_account_roles())

    # personal information of the account
    title = field.StringMedium()
    name = field.StringLong()
    phone = field.StringMedium()
    timezone = field.StringMedium()

    # Flag indicates if account has been locked
    is_locked = field.Boolean(default=False)
    is_active = field.Boolean(default=True)

    # Flag indicates if the email has been verified
    is_verified = field.Boolean(default=False)
    is_idp = field.Boolean(default=False)

    # Counter to save failed login attempts
    login_attempts = field.Integer(default=0)
    password_history = field.List(default=[])

    # Multi factor authentication settings
    mfa_key = field.StringLong()
    mfa_enabled = field.Boolean(default=False)

    verification_token = field.StringLong()
    token_timestamp = field.DateTime()


class Session(Entity):
    """ This class initializes a Session entity for storing session data. """
    # The key of this session
    session_key = field.StringLong(identifier=True)

    # Optional data stored for this session
    session_data = field.Dict()

    # Expiry date for the session
    expire_date = field.DateTime()
