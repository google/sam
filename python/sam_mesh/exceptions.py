"""SAM client exceptions."""


class SAMError(Exception):
    """Base exception for all SAM client errors."""

    pass


class AuthenticationError(SAMError):
    """Raised when passport authentication fails."""

    pass


class HubError(SAMError):
    """Raised when hub communication or OIDC flow fails."""

    pass


class CredentialError(SAMError):
    """Raised when credential store operations fail."""

    pass


class ValidationError(SAMError):
    """Raised when passport or message validation fails."""

    pass


class TimeoutError(SAMError):
    """Raised when an operation times out."""

    pass


class ConnectionError(SAMError):
    """Raised when a peer connection fails."""

    pass
