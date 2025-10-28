"""Custom authentication exceptions (migrated)."""


class AuthError(Exception):
    pass


class SessionError(AuthError):
    pass


class UserError(AuthError):
    pass


class ConfigurationError(AuthError):
    pass


class PermissionError(AuthError):
    pass


