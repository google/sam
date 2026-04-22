"""SAM Hub client for OIDC authentication and passport issuance."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Optional

import httpx

from .exceptions import HubError, ValidationError


@dataclass
class HubDiscovery:
    """OIDC discovery document from the hub."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    device_authorization_endpoint: str
    jwks_uri: str


@dataclass
class DeviceFlowAuth:
    """Device authorization flow response."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int = 5


@dataclass
class DeviceFlowToken:
    """Token response from device flow."""

    access_token: str
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None


class HubClient:
    """Client for SAM Hub OIDC and passport operations."""

    def __init__(self, hub_url: str, client_id: str = "sam-cli", timeout: float = 30.0):
        """
        Initialize the hub client.

        Args:
            hub_url: Base URL of the SAM Hub (e.g. https://hub.example.com).
            client_id: OAuth2 client ID registered with the hub.
            timeout: Request timeout in seconds.
        """
        self.hub_url = hub_url.rstrip("/")
        self.client_id = client_id
        self.timeout = timeout
        self._http_client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> HubClient:
        """Async context manager entry."""
        self._http_client = httpx.AsyncClient(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._http_client:
            await self._http_client.aclose()

    async def discover(self) -> HubDiscovery:
        """
        Fetch the hub's OIDC discovery document.

        Returns:
            HubDiscovery with endpoints.

        Raises:
            HubError: If discovery fails.
        """
        if not self._http_client:
            raise HubError("hub client not initialized (use async context manager)")

        try:
            url = f"{self.hub_url}/.well-known/openid-configuration"
            resp = await self._http_client.get(url)
            resp.raise_for_status()
            data = resp.json()

            return HubDiscovery(
                issuer=data.get("issuer", ""),
                authorization_endpoint=data.get("authorization_endpoint", ""),
                token_endpoint=data.get("token_endpoint", ""),
                device_authorization_endpoint=data.get("device_authorization_endpoint", ""),
                jwks_uri=data.get("jwks_uri", ""),
            )
        except httpx.HTTPError as e:
            raise HubError(f"hub discovery failed: {e}") from e

    async def start_device_flow(self, device_auth_endpoint: str) -> DeviceFlowAuth:
        """
        Start the OAuth2 device authorization grant flow.

        Args:
            device_auth_endpoint: Device authorization endpoint URL.

        Returns:
            DeviceFlowAuth with user code and verification URI.

        Raises:
            HubError: If the flow cannot be started.
        """
        if not self._http_client:
            raise HubError("hub client not initialized (use async context manager)")

        try:
            payload = {
                "client_id": self.client_id,
                "scope": "openid profile email",
            }
            resp = await self._http_client.post(device_auth_endpoint, data=payload)
            resp.raise_for_status()
            data = resp.json()

            return DeviceFlowAuth(
                device_code=data.get("device_code", ""),
                user_code=data.get("user_code", ""),
                verification_uri=data.get("verification_uri", ""),
                verification_uri_complete=data.get("verification_uri_complete", ""),
                expires_in=int(data.get("expires_in", 600)),
                interval=int(data.get("interval", 5)),
            )
        except httpx.HTTPError as e:
            raise HubError(f"device flow initiation failed: {e}") from e

    async def poll_device_token(
        self,
        token_endpoint: str,
        device_flow: DeviceFlowAuth,
        max_wait_secs: Optional[float] = None,
    ) -> DeviceFlowToken:
        """
        Poll the token endpoint until the user approves or the flow expires.

        Args:
            token_endpoint: Token endpoint URL.
            device_flow: Device flow auth response.
            max_wait_secs: Maximum time to wait (defaults to device_flow.expires_in).

        Returns:
            DeviceFlowToken with access token.

        Raises:
            HubError: If polling fails or times out.
        """
        if not self._http_client:
            raise HubError("hub client not initialized (use async context manager)")

        if max_wait_secs is None:
            max_wait_secs = float(device_flow.expires_in)

        deadline = asyncio.get_event_loop().time() + max_wait_secs
        interval = max(device_flow.interval, 1)  # respect minimum 1s

        while True:
            if asyncio.get_event_loop().time() > deadline:
                raise HubError("device flow authorization expired")

            try:
                payload = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_flow.device_code,
                    "client_id": self.client_id,
                }
                resp = await self._http_client.post(token_endpoint, data=payload)

                if resp.status_code == 200:
                    data = resp.json()
                    return DeviceFlowToken(
                        access_token=data.get("access_token", ""),
                        refresh_token=data.get("refresh_token"),
                        expires_in=data.get("expires_in"),
                    )
                elif resp.status_code == 400:
                    error = resp.json().get("error", "")
                    if error == "authorization_pending":
                        await asyncio.sleep(interval)
                        continue
                    elif error == "slow_down":
                        interval = min(interval + 5, 30)
                        await asyncio.sleep(interval)
                        continue
                    else:
                        raise HubError(f"device flow error: {error}")
                else:
                    raise HubError(f"token endpoint returned {resp.status_code}")
            except asyncio.CancelledError:
                raise
            except httpx.HTTPError as e:
                raise HubError(f"device flow polling failed: {e}") from e

    async def issue_passport_biscuit(
        self,
        access_token: str,
        peer_id: str,
        federation_id: str,
        subject: str = "",
        email: str = "",
    ) -> str:
        """
        Request a hub-issued passport biscuit.

        Args:
            access_token: OAuth2 access token from device flow.
            peer_id: This agent's libp2p peer ID.
            federation_id: Federation/mesh ID.
            subject: Optional subject for the biscuit (defaults to peer_id).
            email: Optional email claim to include.

        Returns:
            Hub-issued passport biscuit (ED25519 envelope).

        Raises:
            HubError: If passport issuance fails.
        """
        if not self._http_client:
            raise HubError("hub client not initialized (use async context manager)")

        if not subject:
            subject = peer_id

        try:
            url = f"{self.hub_url}/issue-passport"
            headers = {"Authorization": f"Bearer {access_token}"}
            payload = {
                "peer_id": peer_id,
                "federation": federation_id,
                "mesh_id": federation_id,
                "subject": subject,
                "email": email,
            }
            resp = await self._http_client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            biscuit = data.get("passport_biscuit", "")
            if not biscuit:
                raise ValidationError("hub did not return a passport biscuit")
            return biscuit
        except httpx.HTTPError as e:
            raise HubError(f"passport issuance failed: {e}") from e

    async def fetch_p2p_info(self) -> dict:
        """
        Fetch the hub's P2P peer ID and multiaddrs.

        Returns:
            Dict with 'peer_id' and 'addrs' keys.

        Raises:
            HubError: If the hub is not running in P2P mode or the request fails.
        """
        if not self._http_client:
            raise HubError("hub client not initialized (use async context manager)")

        try:
            url = f"{self.hub_url}/.well-known/sam-hub-p2p"
            resp = await self._http_client.get(url)
            if resp.status_code == 503:
                raise HubError("hub is not running in P2P mode")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            raise HubError(f"failed to fetch hub P2P info: {e}") from e
