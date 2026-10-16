class DecodeError(ValueError):
    """Input cannot be authenticated or interpreted by this profile."""


class AuthenticationError(DecodeError):
    """A record failed authentication. No plaintext is accepted."""


class UnsupportedFormat(DecodeError):
    """A new format needs a separate, verified decoder profile."""
