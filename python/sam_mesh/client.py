"""High-level SAM mesh client for Python."""

from __future__ import annotations

import sys
from typing import Optional

from .auth import PassportClaims, validate_passport_biscuit
from .credentials import CredentialStore, StoredCredentials, default_credential_store
from .exceptions import (
    AuthenticationError,
    CredentialError,
    HubError,
    SAMError,
    ValidationError,
)
from .hub import HubClient


class MeshClient:
    """
    Idiomatic async Python client for the SAM sovereign mesh.

    Provides:
    - OIDC device flow authentication
    - Hub-issued passport biscuit management
    - Credential persistence
    - Peer authentication and validation
    """

    def __init__(
        self,
        hub_url: str,
        *,
        credential_store: Optional[CredentialStore] = None,
        client_id: str = "sam-cli",
    ):
        """
        Initialize the mesh client.

        Args:
            hub_url: Base URL of the SAM Hub.
            credential_store: Credential store (uses default ~/.config/sam/state.db if None).
            client_id: OAuth2 client ID (default: "sam-cli").
        """
        self.hub_url = hub_url
        self.client_id = client_id
        self._cred_store = credential_store
        self._owned_store = credential_store is None
        self._hub_client: Optional[HubClient] = None
        self._local_creds: Optional[StoredCredentials] = None

    def __enter__(self) -> MeshClient:
        """Context manager entry."""
        if self._owned_store and self._cred_store is None:
            self._cred_store = default_credential_store()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()

    async def __aenter__(self) -> MeshClient:
        """Async context manager entry."""
        self.__enter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        self.close()

    def close(self) -> None:
        """Close the client and release resources."""
        if self._cred_store and self._owned_store:
            self._cred_store.close()

    def _ensure_store(self) -> CredentialStore:
        """Ensure credential store is initialized."""
        if self._cred_store is None:
            self._cred_store = default_credential_store()
            self._owned_store = True
        return self._cred_store

    def load_credentials(self) -> Optional[StoredCredentials]:
        """
        Load stored credentials from the local store.

        Returns:
            StoredCredentials or None if no identity exists.
        """
        try:
            store = self._ensure_store()
            return store.load()
        except Exception as e:
            raise CredentialError(f"failed to load credentials: {e}") from e

    async def login(self) -> StoredCredentials:
        """
        Authenticate via the hub using OIDC device authorization grant flow.

        Prompts the user to visit a URL and enter a code. Returns once the user
        completes sign-in and the hub issues a passport biscuit.

        Returns:
            StoredCredentials with access token and passport biscuit.

        Raises:
            HubError: If authentication fails.
            CredentialError: If credential storage fails.
        """
        try:
            async with HubClient(self.hub_url, client_id=self.client_id) as hub:
                # Discover OIDC endpoints
                discovery = await hub.discover()

                # Start device flow
                auth = await hub.start_device_flow(discovery.device_authorization_endpoint)

                # Display codes to user
                verify_url = auth.verification_uri_complete or auth.verification_uri
                print(f"\nOpen this URL in your browser:\n\n  {verify_url}\n", file=sys.stderr)
                if not auth.verification_uri_complete:
                    print(f"And enter code: {auth.user_code}\n", file=sys.stderr)
                print(f"Waiting for authorization (expires in {auth.expires_in}s) …\n", file=sys.stderr)

                # Poll for token
                token_result = await hub.poll_device_token(
                    discovery.token_endpoint,
                    auth,
                    max_wait_secs=float(auth.expires_in),
                )

                # For now, use a placeholder peer ID. In practice, this would come
                # from the libp2p host after it's created.
                # The real flow in Go: build node -> get peer ID -> issue passport
                print("Authorization successful. Issuing passport …\n", file=sys.stderr)

                # TODO: this should come from the libp2p host's PeerID()
                # For now we'll issue without a peer ID and update after node is built
                peer_id = "temp-placeholder"
                biscuit = await hub.issue_passport_biscuit(
                    token_result.access_token,
                    peer_id=peer_id,
                    federation_id="default",
                    subject=peer_id,
                )

                # Store credentials
                creds = StoredCredentials(
                    peer_id=peer_id,
                    hub_url=self.hub_url,
                    access_token=token_result.access_token,
                    refresh_token=token_result.refresh_token or "",
                    passport_biscuit=biscuit,
                )
                store = self._ensure_store()
                store.save(creds)
                self._local_creds = creds

                print(f"Logged in as peer {peer_id}\n", file=sys.stderr)
                print(f"Credentials saved to {store._path}\n", file=sys.stderr)

                return creds
        except HubError:
            raise
        except Exception as e:
            raise HubError(f"authentication failed: {e}") from e

    def validate_passport(
        self,
        biscuit: str,
        *,
        hub_public_key_b64: str,
        expected_peer_id: str,
        expected_mesh_id: str = "default",
    ) -> PassportClaims:
        """
        Validate a passport biscuit.

        Args:
            biscuit: The passport biscuit token.
            hub_public_key_b64: Hub's Ed25519 public key (base64-encoded).
            expected_peer_id: Expected peer ID in the biscuit.
            expected_mesh_id: Expected federation/mesh ID.

        Returns:
            PassportClaims with validated claims.

        Raises:
            ValidationError: If the biscuit is invalid.
        """
        try:
            return validate_passport_biscuit(
                biscuit,
                hub_public_key_b64=hub_public_key_b64,
                expected_peer_id=expected_peer_id,
                expected_mesh_id=expected_mesh_id,
            )
        except ValueError as e:
            raise ValidationError(f"passport validation failed: {e}") from e

    async def fetch_hub_p2p_info(self) -> dict:
        """
        Fetch the hub's P2P bootstrap information.

        Returns:
            Dict with 'peer_id' and 'addrs' keys.

        Raises:
            HubError: If the hub is not running in P2P mode.
        """
        try:
            async with HubClient(self.hub_url) as hub:
                return await hub.fetch_p2p_info()
        except HubError:
            raise
        except Exception as e:
            raise HubError(f"failed to fetch hub P2P info: {e}") from e


__all__ = [
    "MeshClient",
    "HubClient",
    "CredentialStore",
    "StoredCredentials",
    "PassportClaims",
    "SAMError",
    "AuthenticationError",
    "CredentialError",
    "HubError",
    "ValidationError",
]
