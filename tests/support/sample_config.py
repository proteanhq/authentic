"""
Default settings. Override these with settings in the module pointed to
by the PROTEAN_CONFIG environment variable.
"""

####################
# CORE             #
####################

DEBUG = False

# A secret key for this particular Protean installation. Used in secret-key
# hashing algorithms.
SECRET_KEY = 'abcdefghijklmn'

# Flag indicates that we are testing
TESTING = True

# Define the repositories
DATABASES = {
    'default': {
        'PROVIDER': 'protean.impl.repository.dict_repo.DictProvider'
    }
}

# Email Configuration
DEFAULT_FROM_EMAIL = 'johndoe@domain.com'


def build_reset_email(recipient, token):
    """ Build the email for resetting the password"""
    from protean.services.email import EmailMessage

    message = EmailMessage(
        subject='Password Reset Request',
        body=f'Your reset secret token is {token}',
        to=[recipient]
    )
    return message


RESET_EMAIL_CALLBACK = build_reset_email
