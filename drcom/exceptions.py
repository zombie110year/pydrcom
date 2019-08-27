class AuthException(ValueError):
    def __init__(self, msg):
        super().__init__(msg)


class ChallengeException(Exception):
    def __init__(self):
        pass


class LoginException(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class BindPortException(OSError):
    def __init__(self, msg):
        super().__init__(msg)
