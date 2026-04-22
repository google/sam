from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from nacl.signing import VerifyKey

DEFAULT_HUB_ISSUER = "app.sam-mesh.dev"
DEFAULT_RELAY_RENDEZVOUS = "app.sam-mesh.dev"

AUTH_PROTOCOL_ID = "/sam/auth/1.0.0"
A2A_PROTOCOL_ID = "/sam/a2a/1.0.0"
MCP_PROTOCOL_ID = "/sam/mcp/1.0.0"


@dataclass(frozen=True)
class PassportClaims:
    token: str
    issuer: str
    peer_id: str
    mesh_id: str
    subject: str
    claims: Mapping[str, str]
    issued_at: datetime | None


def _b64raw_decode(value: str) -> bytes:
    padding = "=" * ((4 - (len(value) % 4)) % 4)
    return base64.urlsafe_b64decode(value + padding)


def validate_passport_biscuit(
    token: str,
    *,
    hub_public_key_b64: str,
    expected_peer_id: str,
    expected_mesh_id: str,
) -> PassportClaims:
    subject = token.split(";", 1)[0].strip()
    parts = subject.split("|")
    if len(parts) != 3 or parts[0] != "passportv1":
        raise ValueError("invalid passport biscuit subject")

    payload_b64 = ""
    sig_b64 = ""
    for part in parts[1:]:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k == "payload":
            payload_b64 = v
        elif k == "sig":
            sig_b64 = v
    if not payload_b64 or not sig_b64:
        raise ValueError("invalid passport biscuit envelope")

    payload_bytes = _b64raw_decode(payload_b64)
    signature = _b64raw_decode(sig_b64)
    verify_key = VerifyKey(_b64raw_decode(hub_public_key_b64))
    verify_key.verify(payload_bytes, signature)

    payload: dict[str, Any] = json.loads(payload_bytes.decode("utf-8"))
    peer_id = str(payload.get("peer_id", "")).strip()
    mesh_id = str(payload.get("mesh_id") or payload.get("federation_id") or "").strip()
    if peer_id != expected_peer_id.strip():
        raise ValueError("passport peer mismatch")
    if mesh_id != expected_mesh_id.strip():
        raise ValueError("passport mesh mismatch")

    issued_at = None
    raw_ts = payload.get("issued_at")
    if isinstance(raw_ts, str) and raw_ts:
        try:
            issued_at = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except ValueError:
            issued_at = None

    return PassportClaims(
        token=token,
        issuer=str(payload.get("issuer", "")).strip(),
        peer_id=peer_id,
        mesh_id=mesh_id,
        subject=str(payload.get("subject", "")).strip(),
        claims=dict(payload.get("claims") or {}),
        issued_at=issued_at,
    )


async def authenticate_peer(
    *,
    open_stream,
    peer_id: str,
    local_passport: str,
    hub_public_key_b64: str,
    mesh_id: str,
):
    """
    Application-layer auth handshake for /sam/auth/1.0.0.

    Parameters:
    - open_stream: async callable (peer_id, protocol_id) -> stream
      stream must implement async write(bytes), read() -> bytes, close().
    """
    if not local_passport.strip():
        raise ValueError("local passport is required")

    stream = await open_stream(peer_id, AUTH_PROTOCOL_ID)
    try:
        request = json.dumps({"passport": local_passport}).encode("utf-8") + b"\n"
        await stream.write(request)
        raw = await stream.read()
        if not raw:
            raise ValueError("empty passport auth response")
        response = json.loads(raw.decode("utf-8"))
        if not response.get("ok", False):
            raise ValueError(response.get("error", "passport authentication rejected"))
        # Validate our own local token shape early to fail fast on malformed state.
        _ = validate_passport_biscuit(
            local_passport,
            hub_public_key_b64=hub_public_key_b64,
            expected_peer_id=peer_id,
            expected_mesh_id=mesh_id,
        )
    finally:
        await stream.close()
