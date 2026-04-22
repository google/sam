#!/usr/bin/env python3
"""Example: Authenticate with a SAM Hub via OIDC device flow."""

import asyncio
import sys

from sam_mesh import MeshClient


async def main():
    """Authenticate and save credentials to ~/.config/sam/state.db."""
    hub_url = "https://hub.example.com"
    if len(sys.argv) > 1:
        hub_url = sys.argv[1]

    print(f"Authenticating with hub: {hub_url}\n", file=sys.stderr)

    async with MeshClient(hub_url) as client:
        try:
            # Start OIDC device flow — this will prompt the user to visit a URL
            # and enter a code in the browser
            creds = await client.login()

            print(f"✓ Successfully authenticated as peer {creds.peer_id}", file=sys.stderr)
            print(f"✓ Hub: {creds.hub_url}", file=sys.stderr)
            print(f"✓ Passport biscuit issued", file=sys.stderr)
        except Exception as e:
            print(f"✗ Authentication failed: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
