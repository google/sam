#!/usr/bin/env python3
"""Example: Load stored credentials and validate a passport."""

import sys

from sam_mesh import MeshClient, ValidationError


def main():
    """Load and display stored credentials."""
    client = MeshClient("https://hub.example.com")

    try:
        creds = client.load_credentials()

        if not creds:
            print("No stored credentials found. Run login.py first.", file=sys.stderr)
            sys.exit(1)

        print(f"Peer ID:           {creds.peer_id}", file=sys.stderr)
        print(f"Hub URL:           {creds.hub_url}", file=sys.stderr)
        print(f"Passport Biscuit:  {creds.passport_biscuit[:50]}...", file=sys.stderr)

        if creds.token_expiry:
            print(f"Token expires at:  {creds.token_expiry}", file=sys.stderr)

        print("\nTo use credentials in a mesh node, pass the passport biscuit:", file=sys.stderr)
        print(f"  passport = '{creds.passport_biscuit}'", file=sys.stderr)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
