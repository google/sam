from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict


class SQLiteTrustCache:
    def __init__(self, db_path: str | Path):
        self._path = str(db_path)
        self._conn = sqlite3.connect(self._path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS peer_scores (
                peer_id TEXT PRIMARY KEY,
                total INTEGER NOT NULL,
                count INTEGER NOT NULL,
                score REAL NOT NULL
            )
            """
        )
        self._conn.commit()

    def update(self, peer_id: str, rating: int) -> float:
        if rating < -1 or rating > 1:
            raise ValueError("rating must be -1..1")
        peer = peer_id.strip()
        if not peer:
            raise ValueError("peer_id is required")

        row = self._conn.execute(
            "SELECT total, count FROM peer_scores WHERE peer_id = ?", (peer,)
        ).fetchone()
        total = int(row[0]) if row else 0
        count = int(row[1]) if row else 0
        total += rating
        count += 1
        score = total / count

        self._conn.execute(
            """
            INSERT INTO peer_scores(peer_id, total, count, score)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(peer_id)
            DO UPDATE SET total = excluded.total, count = excluded.count, score = excluded.score
            """,
            (peer, total, count, score),
        )
        self._conn.commit()
        return score

    def score(self, peer_id: str) -> float:
        row = self._conn.execute(
            "SELECT score FROM peer_scores WHERE peer_id = ?", (peer_id.strip(),)
        ).fetchone()
        if not row:
            return 0.0
        return float(row[0])

    def snapshot(self) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for peer_id, score in self._conn.execute("SELECT peer_id, score FROM peer_scores"):
            out[str(peer_id)] = float(score)
        return out

    def close(self) -> None:
        self._conn.close()
