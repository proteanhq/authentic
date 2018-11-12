""" Configuration variables used by Authentic """


class AuthenticConfig:
    """ Default configurations for the Authentic application """

    ACCOUNT_ENTITY = 'authentic.entities.Account'

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
