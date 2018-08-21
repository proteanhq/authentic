"""Account and Authentication Entities"""

from enum import Enum

from protean.core.entity import BaseEntity


class Role(Enum):
    """Enum class for storing Account Roles"""
    ADMIN = 'ADMIN'


ROLES = [role.value for role in Role]


class Account(BaseEntity):
    """
    This class initializes an Account Entity.
    """

    _fields = [
        'id', 'username', 'name', 'title', 'roles', 'location', 'password', 'email', 'phone',
        'created_at', 'updated_at', 'created_by', 'updated_by', 'timezone', 'verification_token',
        'token_timestamp', 'is_archived', 'is_active', 'customer_id', 'bookmarks', 'profiles',
        'is_verified', 'tenant_id', 'is_idp', 'temp_token', 'temp_token_timestamp',
        'login_attempts', 'is_locked', 'password_history', 'mfa_enabled', 'mfa_key'
    ]
    _mandatory = ['username', 'password', 'email']
    _defaults = {
        'password_history': [],
        'is_locked': False,
        'login_attempts': 0,
        'is_archived': False,
        'is_active': True
    }
    _unique = ['username', 'email']
    _field_definitions = [
        'id:IDENTIFIER:IDENTIFIER',
        'username:STRING:MEDIUM',
        'name:STRING:LONG',
        'title:STRING:MEDIUM',
        'roles:STRING:MEDIUM',
        'location.city:STRING:MEDIUM',
        'location.city_id:STRING:MEDIUM',
        'location.country:STRING:MEDIUM',
        'location.country_id:STRING:MEDIUM',
        'location.state:STRING:MEDIUM',
        'location.state_id:STRING:MEDIUM',
        'password:STRING:LONG',
        'email:STRING:LONG',
        'phone:STRING:MEDIUM',
        'timezone:STRING:MEDIUM',
        'created_by:IDENTIFIER:IDENTIFIER',
        'updated_by:IDENTIFIER:IDENTIFIER',
        'is_archived:BOOLEAN',
        'is_active:BOOLEAN',
        'customer_id:IDENTIFIER:IDENTIFIER',
        'bookmarks.entity_id:IDENTIFIER:CUSTOM_IDENTIFIER',
        'bookmarks.entity_type:STRING:SHORT',
        'bookmarks.created_at:TIMESTAMP',
        'bookmarks.updated_at:TIMESTAMP',
        'created_at:TIMESTAMP',
        'updated_at:TIMESTAMP',
        'is_verified:BOOLEAN',
        'tenant_id:IDENTIFIER:CUSTOM_IDENTIFIER',
        'is_idp:BOOLEAN',
        'temp_token:STRING:LONG',
        'temp_token_timestamp:TIMESTAMP',
        'login_attempts:INTEGER',
        'mfa_enabled:BOOLEAN',
        'mfa_key:STRING:LONG',
        'password_history:LIST'
    ]
