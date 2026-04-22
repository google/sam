"""SAM Mesh — Python client for the Sovereign Agent Mesh."""

from .auth import (
    A2A_PROTOCOL_ID,
    AUTH_PROTOCOL_ID,
    DEFAULT_HUB_ISSUER,
    DEFAULT_RELAY_RENDEZVOUS,
    MCP_PROTOCOL_ID,
    PassportClaims,
    authenticate_peer,
    validate_passport_biscuit,
)
from .client import MeshClient
from .credentials import CredentialStore, StoredCredentials, default_credential_store
from .exceptions import (
    AuthenticationError,
    ConnectionError,
    CredentialError,
    HubError,
    SAMError,
    TimeoutError,
    ValidationError,
)
from .hub import HubClient
from .trust_cache import SQLiteTrustCache

__version__ = "0.1.0"

__all__ = [
    # High-level client
    "MeshClient",
    # Hub and auth
    "HubClient",
    # Credentials
    "CredentialStore",
    "StoredCredentials",
    "default_credential_store",
    # Passport validation
    "PassportClaims",
    "validate_passport_biscuit",
    "authenticate_peer",
    # Protocol IDs
    "AUTH_PROTOCOL_ID",
    "A2A_PROTOCOL_ID",
    "MCP_PROTOCOL_ID",
    # Constants
    "DEFAULT_HUB_ISSUER",
    "DEFAULT_RELAY_RENDEZVOUS",
    # Exceptions
    "SAMError",
    "AuthenticationError",
    "CredentialError",
    "HubError",
    "ValidationError",
    "TimeoutError",
    "ConnectionError",
    # Trust cache
    "SQLiteTrustCache",
]
