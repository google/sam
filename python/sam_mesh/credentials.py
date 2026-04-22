"""Local credential store for SAM identities."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from .exceptions import CredentialError


@dataclass
class StoredCredentials:
    """Persisted identity state in the SAM credential store."""

    peer_id: str
    """Local libp2p peer ID."""

    hub_url: str
    """Hub the user authenticated against."""

    access_token: str
    """OAuth2 access token returned by the Hub."""

    passport_biscuit: str
    """Hub-issued biscuit binding identity to peer/federation."""

    refresh_token: str = ""
    """Refresh token for silent token renewal."""

    token_expiry: Optional[datetime] = None
    """When the access token expires."""

    def to_dict(self) -> dict:
        """Serialize to dict for JSON storage."""
        data = asdict(self)
        if self.token_expiry:
            data["token_expiry"] = self.token_expiry.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> StoredCredentials:
        """Deserialize from dict."""
        if "token_expiry" in data and data["token_expiry"]:
            try:
                data["token_expiry"] = datetime.fromisoformat(
                    data["token_expiry"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                data["token_expiry"] = None
        return cls(**data)


class CredentialStore:
    """Reads and writes SAM credentials from a local SQLite store."""

    def __init__(self, db_path: str | Path):
        """
        Initialize the credential store.

        Args:
            db_path: Path to SQLite database file.
        """
        self._path = str(db_path)
        self._conn = sqlite3.connect(self._path)
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                key TEXT PRIMARY KEY,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def load(self) -> Optional[StoredCredentials]:
        """
        Load stored credentials. Returns None if no identity exists.

        Returns:
            StoredCredentials or None.

        Raises:
            CredentialError: If load fails.
        """
        try:
            row = self._conn.execute(
                "SELECT data FROM credentials WHERE key = 'local'"
            ).fetchone()
            if not row:
                return None
            data = json.loads(row[0])
            return StoredCredentials.from_dict(data)
        except Exception as e:
            raise CredentialError(f"failed to load credentials: {e}") from e

    def save(self, creds: StoredCredentials) -> None:
        """
        Save credentials to the store.

        Args:
            creds: Credentials to save.

        Raises:
            CredentialError: If save fails.
        """
        try:
            data = json.dumps(creds.to_dict())
            self._conn.execute(
                """
                INSERT INTO credentials(key, data)
                VALUES ('local', ?)
                ON CONFLICT(key) DO UPDATE SET data = excluded.data
                """,
                (data,),
            )
            self._conn.commit()
        except Exception as e:
            raise CredentialError(f"failed to save credentials: {e}") from e

    def delete(self) -> None:
        """Delete stored credentials."""
        try:
            self._conn.execute("DELETE FROM credentials WHERE key = 'local'")
            self._conn.commit()
        except Exception as e:
            raise CredentialError(f"failed to delete credentials: {e}") from e

    def close(self) -> None:
        """Close the credential store."""
        if self._conn:
            self._conn.close()

    def __enter__(self) -> CredentialStore:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()


def default_credential_store() -> CredentialStore:
    """
    Return a credential store using the default SAM state directory.

    The default path is ~/.config/sam/state.db.

    Returns:
        CredentialStore instance.

    Raises:
        CredentialError: If the default path cannot be resolved.
    """
    try:
        config_dir = Path.home() / ".config" / "sam"
        config_dir.mkdir(parents=True, exist_ok=True)
        db_path = config_dir / "state.db"
        return CredentialStore(str(db_path))
    except Exception as e:
        raise CredentialError(f"failed to initialize default credential store: {e}") from e
