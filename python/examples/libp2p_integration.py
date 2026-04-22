#!/usr/bin/env python3
"""Example: Integrate SAM client with libp2p host and authenticate peers."""

import asyncio
from typing import Any

from sam_mesh import MeshClient, authenticate_peer, validate_passport_biscuit


async def example_with_libp2p_host():
    """
    Example showing how to integrate SAM auth with a libp2p host.

    In real usage:
    1. Create a libp2p host (using py-libp2p)
    2. Load or authenticate with the SAM hub to get a passport
    3. Set up stream handlers for /sam/auth/1.0.0 and other SAM protocols
    4. Call authenticate_peer when connecting to other agents
    """

    # Load credentials
    client = MeshClient("https://hub.example.com")
    creds = client.load_credentials()

    if not creds:
        print("No credentials found. Run login.py first.")
        return

    print(f"Using peer ID: {creds.peer_id}")
    print(f"Passport biscuit: {creds.passport_biscuit[:50]}...")

    # In a real scenario, you would:

    # 1. Create a libp2p host
    #    host = await create_libp2p_host(...)

    # 2. Register the SAM auth protocol handler
    #    host.set_stream_handler("/sam/auth/1.0.0", handle_auth_stream)

    # 3. When connecting to a peer, authenticate them
    #    await authenticate_peer(
    #        open_stream=host.new_stream,
    #        peer_id=remote_peer_id,
    #        local_passport=creds.passport_biscuit,
    #        hub_public_key_b64="...",  # from hub
    #        mesh_id="default",
    #    )

    # 4. Validate their passport
    #    claims = validate_passport_biscuit(
    #        their_passport,
    #        hub_public_key_b64="...",
    #        expected_peer_id=remote_peer_id,
    #        expected_mesh_id="default",
    #    )
    #    print(f"Authenticated peer: {claims.subject}")

    print("\nExample structure shown above. See auth.py for protocol details.")


if __name__ == "__main__":
    asyncio.run(example_with_libp2p_host())
