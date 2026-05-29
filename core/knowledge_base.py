"""
Guardian Knowledge Base — A1 RAG infrastructure.

Provides grounded retrieval over CVE / CWE / MITRE ATT&CK / nuclei-template
metadata so the Analyst stops hallucinating CVE references. SQLite-only
(stdlib) — no new infra dep. FTS5 powers the lexical search; an optional
embedding column accelerates fuzzy semantic matching when the
``sentence-transformers`` extra is installed.

## Schema

```
entries(
    id        TEXT PRIMARY KEY,    -- CVE-2024-12345 / CWE-79 / T1190 / nuclei-template-id
    kind      TEXT,                -- cve | cwe | attck | template
    title     TEXT,
    summary   TEXT,
    severity  TEXT,                -- critical|high|medium|low|info|unknown
    cvss      REAL,                -- canonical base score when known
    cwe       TEXT,                -- comma-list
    refs      TEXT,                -- JSON list of URLs
    updated   TEXT                 -- ISO date
)
fts(id, title, summary, refs)      -- FTS5 virtual, content=entries
```

Embeddings live in a sibling table ``embeddings(id, vec BLOB)`` populated
only when the optional dep is installed. The retriever falls back to FTS5
when embeddings are unavailable.

## Public surface

```
KnowledgeBase(path).query(text, k=5, kind=None) -> list[KBHit]
KnowledgeBase(path).upsert(entries: Iterable[KBEntry]) -> int
KnowledgeBase(path).has_corpus(kind) -> bool
```

The ``cli/commands/kb.py`` Typer module wraps the maintenance side — fetch
NVD/CWE/ATT&CK/nuclei feeds and call ``upsert``. This module is the
read/write store; corpora download is opt-in and explicit.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


_DEFAULT_DB = Path.home() / ".guardian" / "kb" / "kb.sqlite3"


@dataclass
class KBEntry:
    """One KB record. ``id`` is canonical and unique across kinds."""

    id: str
    kind: str          # cve | cwe | attck | template
    title: str
    summary: str = ""
    severity: str = "unknown"
    cvss: Optional[float] = None
    cwe: str = ""
    refs: List[str] = field(default_factory=list)
    updated: str = ""


@dataclass
class KBHit:
    """A single retrieval result. ``score`` is FTS5 bm25 (lower = better)
    or 1 - cosine when embeddings rank. We normalise to "higher = better"
    in ``KnowledgeBase.query`` so callers don't need to care which path
    produced the result.
    """

    entry: KBEntry
    score: float


# ── Schema ───────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id        TEXT PRIMARY KEY,
    kind      TEXT NOT NULL,
    title     TEXT NOT NULL,
    summary   TEXT NOT NULL DEFAULT '',
    severity  TEXT NOT NULL DEFAULT 'unknown',
    cvss      REAL,
    cwe       TEXT NOT NULL DEFAULT '',
    refs      TEXT NOT NULL DEFAULT '[]',
    updated   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_entries_kind ON entries(kind);

CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
    id UNINDEXED, title, summary, refs,
    content='entries', content_rowid='rowid', tokenize='porter'
);

-- Triggers keep FTS in sync with entries on insert/update/delete.
CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
    INSERT INTO fts(rowid, id, title, summary, refs)
    VALUES (new.rowid, new.id, new.title, new.summary, new.refs);
END;
CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
    INSERT INTO fts(fts, rowid, id, title, summary, refs)
    VALUES('delete', old.rowid, old.id, old.title, old.summary, old.refs);
END;
CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE ON entries BEGIN
    INSERT INTO fts(fts, rowid, id, title, summary, refs)
    VALUES('delete', old.rowid, old.id, old.title, old.summary, old.refs);
    INSERT INTO fts(rowid, id, title, summary, refs)
    VALUES (new.rowid, new.id, new.title, new.summary, new.refs);
END;

CREATE TABLE IF NOT EXISTS embeddings (
    id    TEXT PRIMARY KEY REFERENCES entries(id) ON DELETE CASCADE,
    vec   BLOB NOT NULL
);
"""


_FTS_SAFE_RE = re.compile(r"[^A-Za-z0-9_ ]+")


def _fts_sanitize(query: str) -> str:
    """FTS5 has its own grammar; quotes, parens, hyphens, reserved keywords
    (AND/OR/NOT/NEAR) are all unsafe.

    We strip everything except word chars + space, then wrap each token in
    double quotes to escape FTS5 keywords, then join with OR so partial
    matches still surface. Empty after cleaning ⇒ caller skips FTS.
    """
    cleaned = _FTS_SAFE_RE.sub(" ", query).strip()
    if not cleaned:
        return ""
    tokens = [t for t in cleaned.split() if len(t) >= 2]
    if not tokens:
        return ""
    # Quoting each token makes it a literal — neutralises FTS5 keywords.
    return " OR ".join(f'"{t}"' for t in tokens)


# ── KnowledgeBase ────────────────────────────────────────────────────────────


class KnowledgeBase:
    """Read/write SQLite-backed KB.

    Constructed cheap — schema applied on first connection. ``query`` is
    safe to call before any corpus has been ingested (returns empty list).

    Thread-safety: SQLite handles per-instance connection serialisation; we
    don't share connections across threads. Async callers that need this
    from a hot path should ``await asyncio.to_thread(kb.query, ...)``.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else _DEFAULT_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None

    # ── Connection lifecycle ─────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.path)
            self._conn.executescript(_SCHEMA)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ── Inspection ───────────────────────────────────────────────────────────

    def has_corpus(self, kind: str) -> bool:
        """Cheap check before kicking off a corpus rebuild."""
        cur = self._connect().execute(
            "SELECT 1 FROM entries WHERE kind = ? LIMIT 1", (kind,)
        )
        return cur.fetchone() is not None

    def stats(self) -> Dict[str, int]:
        """Per-kind row counts. Used by ``guardian kb status``."""
        cur = self._connect().execute(
            "SELECT kind, COUNT(*) AS n FROM entries GROUP BY kind"
        )
        return {row["kind"]: row["n"] for row in cur.fetchall()}

    # ── Write path ───────────────────────────────────────────────────────────

    def upsert(self, entries: Iterable[KBEntry]) -> int:
        """Insert or replace a batch.

        Returns the number of rows written. Caller is responsible for
        de-duping at the source — the PK constraint handles collisions but
        wastes a write per duplicate.
        """
        rows = []
        for e in entries:
            rows.append((
                e.id,
                e.kind,
                e.title[:500],
                e.summary[:5000],
                e.severity,
                e.cvss,
                e.cwe,
                json.dumps(e.refs[:20]),
                e.updated,
            ))

        if not rows:
            return 0

        conn = self._connect()
        with conn:
            conn.executemany(
                "INSERT OR REPLACE INTO entries "
                "(id, kind, title, summary, severity, cvss, cwe, refs, updated) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                rows,
            )
        return len(rows)

    def upsert_embedding(self, entry_id: str, vector: List[float]) -> None:
        """Persist one entry's embedding. Format = float32 little-endian."""
        blob = struct.pack(f"<{len(vector)}f", *vector)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO embeddings(id, vec) VALUES (?, ?)",
                (entry_id, blob),
            )

    # ── Query ────────────────────────────────────────────────────────────────

    def query(
        self,
        text: str,
        k: int = 5,
        kind: Optional[str] = None,
    ) -> List[KBHit]:
        """Top-k retrieval.

        Uses FTS5 by default. If an embedding model is available AND the
        query has any matches in ``embeddings``, the FTS shortlist is
        re-ranked by cosine similarity.
        """
        text = (text or "").strip()
        if not text:
            return []

        conn = self._connect()
        fts_query = _fts_sanitize(text)
        if not fts_query:
            return []

        sql = (
            "SELECT e.*, bm25(fts) AS rank "
            "FROM fts JOIN entries e ON e.rowid = fts.rowid "
            "WHERE fts MATCH ?"
        )
        params: List[Any] = [fts_query]
        if kind:
            sql += " AND e.kind = ?"
            params.append(kind)
        sql += " ORDER BY rank LIMIT ?"
        params.append(max(k, 1) * 4)  # over-fetch; reranker may winnow

        rows = conn.execute(sql, params).fetchall()
        if not rows:
            return []

        hits = [
            KBHit(entry=_row_to_entry(row), score=_bm25_to_score(row["rank"]))
            for row in rows
        ]

        # Optional rerank — only if embeddings exist for shortlisted IDs.
        reranker = _maybe_load_reranker()
        if reranker is not None:
            hits = _rerank_with_embeddings(conn, reranker, text, hits)

        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:k]


# ── helpers ──────────────────────────────────────────────────────────────────


def _row_to_entry(row: sqlite3.Row) -> KBEntry:
    try:
        refs = json.loads(row["refs"]) if row["refs"] else []
    except json.JSONDecodeError:
        refs = []
    if not isinstance(refs, list):
        refs = []
    return KBEntry(
        id=row["id"],
        kind=row["kind"],
        title=row["title"],
        summary=row["summary"],
        severity=row["severity"],
        cvss=row["cvss"],
        cwe=row["cwe"],
        refs=refs,
        updated=row["updated"],
    )


def _bm25_to_score(bm25: float) -> float:
    """bm25 is "lower is better". Flip + squash to (0, 1]."""
    if bm25 is None:
        return 0.0
    return 1.0 / (1.0 + max(bm25, 0.0))


def _maybe_load_reranker():
    """Return an embedding model if sentence-transformers is installed,
    else ``None``. Cached at module level so we only pay import cost once.
    """
    global _RERANKER_CACHE
    if _RERANKER_CACHE is _SENTINEL:
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            _RERANKER_CACHE = SentenceTransformer("all-MiniLM-L6-v2")
        except Exception:  # pragma: no cover — optional dep missing
            _RERANKER_CACHE = None
    return _RERANKER_CACHE


_SENTINEL = object()
_RERANKER_CACHE: Any = _SENTINEL


def _rerank_with_embeddings(
    conn: sqlite3.Connection,
    model,
    query_text: str,
    hits: List[KBHit],
) -> List[KBHit]:
    """Cosine-rerank a shortlist. Skips entries with no embedding row."""
    if not hits:
        return hits

    ids = [h.entry.id for h in hits]
    placeholder = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT id, vec FROM embeddings WHERE id IN ({placeholder})",
        ids,
    ).fetchall()

    if not rows:
        return hits  # No embeddings for this shortlist — keep FTS order.

    vecs: Dict[str, List[float]] = {}
    for row in rows:
        blob = row["vec"]
        n = len(blob) // 4
        vecs[row["id"]] = list(struct.unpack(f"<{n}f", blob))

    if not vecs:
        return hits

    q_vec = model.encode([query_text], normalize_embeddings=True)[0].tolist()

    new_hits: List[KBHit] = []
    for h in hits:
        v = vecs.get(h.entry.id)
        if v is None:
            new_hits.append(h)
            continue
        cos = _cosine(q_vec, v)
        # Blend: 0.3 * fts_score + 0.7 * cosine.
        new_hits.append(KBHit(entry=h.entry, score=0.3 * h.score + 0.7 * cos))
    return new_hits


def _cosine(a: List[float], b: List[float]) -> float:
    """Numerically defensive cosine — short-circuits on zero norms."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


# ── CLI helper: format hits for prompt injection ─────────────────────────────


def hits_to_prompt_block(hits: List[KBHit], max_chars: int = 2000) -> str:
    """Render top-k hits as a fenced reference block for the analyst prompt.

    Caller is expected to wrap the returned text via ``utils.sanitize.
    wrap_untrusted`` before inlining it into a system prompt — even
    grounded references can carry injected instructions if a CVE summary
    was poisoned upstream.
    """
    if not hits:
        return ""

    lines = ["[BEGIN_KB_REFERENCES]"]
    used = 0
    for h in hits:
        e = h.entry
        line = (
            f"- {e.id} ({e.kind}, severity={e.severity}"
            + (f", cvss={e.cvss}" if e.cvss is not None else "")
            + f"): {e.title}"
        )
        if e.summary:
            line += f" — {e.summary[:300]}"
        if used + len(line) > max_chars:
            break
        lines.append(line)
        used += len(line) + 1
    lines.append("[END_KB_REFERENCES]")
    return "\n".join(lines)
