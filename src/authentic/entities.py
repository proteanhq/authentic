"""Account and Authentication Entities"""

from enum import Enum

from protean.core.entity import Entity
from protean.core import field


class Role(Enum):
    """Enum class for storing Account Roles"""
    ADMIN = 'ADMIN'


ROLES = [role.value for role in Role]


class Account(Entity):
    """
    This class initializes an Account Entity.
    """
    id = field.Auto(identifier=True)

    username = field.String(required=True)
    password = field.String(required=True)
    email = field.String(required=True)
    name = field.String()
    title = field.String()
    phone = field.String()
    timezone = field.String()
    is_locked = field.Boolean(default=False)
    is_active = field.Boolean(default=True)
    login_attempts = field.Integer(default=0)
    password_history = field.List()
    is_idp = field.Boolean(default=False)
    mfa_enabled = field.Boolean(default=False)
    mfa_key = field.String()
