""" Configuration variables used by Authentic """


class AuthenticConfig:
    """ Default configurations for the Authentic application """

    # The default password rules for the application
    PASSWORD_RULES = {
      "min_length": 5,
      "max_length": 20,
      "upper_case": True,
      "lower_case": True,
      "digit": True,
      "max_invalid_attempts": 5,
      "min_topology_changes": 3,
      "blacklist": [
        "test",
        "Test",
        "Test@123"
      ]
    }

    # Default list of roles allowed for the application
    ROLES = ('ADMIN',)
