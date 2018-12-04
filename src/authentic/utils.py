"""Utility Methods for Authentication"""

import re

from importlib import import_module

from passlib.hash import pbkdf2_sha256

from protean.conf import active_config
from protean.utils.importlib import perform_import


REGEX_MAPPINGS = {
    "upper_case": '.*[A-Z].*',
    "lower_case": '.*[a-z].*',
    "digit": '.*[0-9].*'
}


class PasswordHandler:
    """This module defines limitations for the password"""

    def __init__(self, config):
        self.config = config

    def is_valid(self, password, old_password_list):
        """This method validates password strength"""
        try:
            if self.is_password_strong(password) and \
                    self.validate_if_blacklisted(password) and \
                    self.check_password_history(password, old_password_list):
                return {"message": "Valid password"}
        except Exception as error:
            return {"message": "Invalid password", "error": error.args[0]}

    def validate_if_blacklisted(self, password):
        """Validate if the password is blacklisted"""
        if password in self.config.get("blacklist"):
            raise ValueError("Avoid using common passwords")

        return True

    def is_password_strong(self, password):
        """Validate if strong password"""
        constrains = ['upper_case', 'lower_case', 'digit']
        generic_message = "Password should contain" + \
            ",".join([" 1 {}".format(m.replace('_', ' '))
                      for m in constrains if self.config.get(m)])

        generic_message += " and length should be from {} to {}".\
            format(self.config.get("min_length"),
                   self.config.get("max_length"))

        if not (self.config.get("min_length") <= len(password) <=
                self.config.get("max_length")):
            raise ValueError(generic_message)
        elif self.config.get("upper_case") and not \
                bool(re.match(REGEX_MAPPINGS["upper_case"], password)):
            raise ValueError(generic_message)
        elif self.config.get("lower_case") and not \
                bool(re.match(REGEX_MAPPINGS["lower_case"], password)):
            raise ValueError(generic_message)
        elif self.config.get("digit") and not \
                bool(re.match(REGEX_MAPPINGS["digit"], password)):
            raise ValueError(generic_message)

        return True

    def check_password_history(self, password, old_password_list):
        """Validation for the password history"""
        for old_pass in old_password_list:
            if pbkdf2_sha256.verify(password, old_pass):
                raise ValueError(
                    "Password should not match previously used passwords")

        return True


def validate_new_password(new_password, old_password_list):
    """Validate New Password"""

    password_handler = PasswordHandler(active_config.PASSWORD_RULES)
    response = password_handler.is_valid(new_password, old_password_list)
    if response['message'] == 'Valid password':
        response['is_valid'] = True
    else:
        response['is_valid'] = False

    return response


def modify_password_history(old_password, input_password_history):
    """Tweak Password History"""

    password_history = input_password_history[:]
    password_config = active_config.PASSWORD_RULES
    extra_count = len(password_history) - password_config['min_topology_changes']
    if extra_count >= 0:
        for _ in range(extra_count + 1):
            password_history.pop(0)
    password_history.append(old_password)

    return password_history


def get_auth_backend():
    """ Load the authentication backend """
    auth_backend = import_module(active_config.AUTHENTICATION_BACKEND)
    return auth_backend


def get_account_roles():
    """ Get the roles for the account from the settings"""
    account_roles = perform_import(active_config.ACCOUNT_ROLES)
    return account_roles
