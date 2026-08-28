"""Transactional SQLite Deduplication Cache & MinHash Index."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Dict, List, Optional, Set, Tuple

from enricher.minhash import compute_minhash_signature, estimate_jaccard_similarity
from enricher.models import ThreatAdvisory, ThreatDigest, utcnow_iso


class ThreatFeedCache:
    """Persistent SQLite deduplication and historical threat cache."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS seen_threats (
                    id TEXT PRIMARY KEY,
                    cve_id TEXT,
                    raw_hash TEXT NOT NULL UNIQUE,
                    minhash_sig TEXT NOT NULL,
                    title TEXT NOT NULL,
                    source_feed TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_threat_cve ON seen_threats(cve_id);
                CREATE INDEX IF NOT EXISTS idx_threat_hash ON seen_threats(raw_hash);
            """)

    def is_exact_duplicate(self, raw_hash: str) -> bool:
        """Check if identical content hash was previously recorded."""
        with self._lock, self._get_connection() as conn:
            row = conn.execute("SELECT 1 FROM seen_threats WHERE raw_hash = ?", (raw_hash,)).fetchone()
            return row is not None

    def get_recent_signatures(self, limit: int = 1000) -> List[Tuple[str, List[int]]]:
        """Fetch recently stored MinHash signatures from database."""
        with self._lock, self._get_connection() as conn:
            rows = conn.execute(
                "SELECT id, minhash_sig FROM seen_threats ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            result = []
            for r in rows:
                sig_list = json.loads(r["minhash_sig"])
                result.append((r["id"], sig_list))
            return result

    def record_advisory(self, advisory: ThreatAdvisory, minhash_sig: List[int]) -> None:
        """Store newly seen threat advisory in persistent cache."""
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO seen_threats (
                    id, cve_id, raw_hash, minhash_sig, title, source_feed, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    advisory.id,
                    advisory.cve_id,
                    advisory.raw_hash,
                    json.dumps(minhash_sig),
                    advisory.title,
                    advisory.source_feed.value,
                    utcnow_iso(),
                ),
            )

    def deduplicate_stream(
        self,
        incoming: List[ThreatAdvisory],
        similarity_threshold: float = 0.70,
        persist: bool = True,
    ) -> ThreatDigest:
        """Filter out exact and fuzzy MinHash duplicates from advisory stream.

        Args:
            incoming: List of raw parsed ThreatAdvisory models.
            similarity_threshold: Jaccard similarity cutoff (0.0 to 1.0) for fuzzy matches.
            persist: Whether to store newly identified unique advisories into SQLite cache.

        Returns:
            ThreatDigest containing only deduplicated, unique advisories and metrics.
        """
        historical_sigs = self.get_recent_signatures()
        session_sigs: List[Tuple[str, List[int]]] = []

        unique_advisories: List[ThreatAdvisory] = []
        dup_count = 0
        seen_cves: Set[str] = set()

        for adv in incoming:
            # 1. Exact CVE duplicate in same batch
            if adv.cve_id and adv.cve_id in seen_cves:
                dup_count += 1
                continue

            # 2. Exact content hash match in DB
            if self.is_exact_duplicate(adv.raw_hash):
                dup_count += 1
                continue

            # 3. Compute MinHash signature over title + description
            sig = compute_minhash_signature(f"{adv.title} {adv.description}")

            # Check similarity against historical and current batch
            is_fuzzy_dup = False
            for _, existing_sig in historical_sigs + session_sigs:
                sim = estimate_jaccard_similarity(sig, existing_sig)
                if sim >= similarity_threshold:
                    is_fuzzy_dup = True
                    break

            if is_fuzzy_dup:
                dup_count += 1
                continue

            # Unique advisory
            unique_advisories.append(adv)
            session_sigs.append((adv.id, sig))
            if adv.cve_id:
                seen_cves.add(adv.cve_id)

            if persist:
                self.record_advisory(adv, sig)

        critical_count = sum(
            1 for a in unique_advisories if a.is_known_exploited or (a.cvss_score is not None and a.cvss_score >= 8.5)
        )

        return ThreatDigest(
            advisories=unique_advisories,
            total_ingested=len(incoming),
            unique_count=len(unique_advisories),
            duplicate_count=dup_count,
            critical_count=critical_count,
        )
