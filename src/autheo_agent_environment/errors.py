"""Typed errors so transports (HTTP API, CLI) can map failures without string matching."""


class ConflictError(ValueError):
    """Idempotency/replay conflict: the same identifier was reused for different content."""


class NotFoundError(LookupError):
    """A referenced identity, mandate, receipt or environment does not exist locally."""


class AuthorizationError(PermissionError):
    """The caller is not permitted to perform the operation."""
