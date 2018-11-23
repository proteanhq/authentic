"""Account and Authentication Entities"""

from protean.core.entity import Entity
from protean.core import field


class Account(Entity):
    """
    This class initializes an Account Entity.
    """
    # List of roles for the Account
    roles = field.List()

    # username, email and password for auth
    username = field.String(required=True, unique=True)
    email = field.String(required=True, unique=True)
    password = field.String(required=True)

    # personal information of the account
    title = field.String()
    name = field.String()
    phone = field.String()
    timezone = field.String()

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
    mfa_key = field.String()
    mfa_enabled = field.Boolean(default=False)

    verification_token = field.String()
    token_timestamp = field.DateTime()


class Token(Entity):
    """
    This class initializes a Token entity for storing verification tokens.
    """
    token = field.String()
    timestamp = field.String()
