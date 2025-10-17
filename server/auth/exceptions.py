"""Custom authentication exceptions."""

class AuthError(Exception):
    """Base authentication error."""
    pass

class SessionError(AuthError):
    """Session-related error."""
    pass


class UserError(AuthError):
    """User-related error."""
    pass

class ConfigurationError(AuthError):
    """Configuration-related error."""
    pass

class PermissionError(AuthError):
    """Permission-related error."""
    pass
