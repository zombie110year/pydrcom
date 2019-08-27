class AuthException(ValueError):
    def __init__(self, msg):
        super().__init__(msg)


class ChallengeException(ValueError):
    def __init__(self, msg):
        super().__init__(msg)


class LoginException(AuthException):
    pass


class BindPortException(OSError):
    def __init__(self, msg):
        super().__init__(msg)


class KeepAliveException(ValueError):
    def __init__(self, msg):
        super().__init__(msg)
