"""Store-backend contract for the authoritative fact store.

One contract, two backends:

- ``JsonStore`` wraps today's ``facts.json`` behavior (load via
  ``_facts.load_facts``, write via atomic ``_store.secure_write_json``): the default.
- ``SqliteStore`` holds the same facts in a single WAL-mode SQLite database
  (``brain.db``), value-identically: modeled fields become columns, structured
  fields (``evidence``, ``attestation``) are stored as canonical JSON text, and
  every unmodeled or non-scalar field rides an ``extra`` JSON column so any
  fact round-trips losslessly. Attestations are preserved verbatim: they sign
  fact VALUES, not container bytes, so migration needs no re-signing.

Backend selection (``resolve_store``) is deliberately conservative: JSON is
the default and stays authoritative until SQLite is EXPLICITLY selected via
``NOCKBRAIN_STORE=sqlite`` or a ``store-v2`` marker file next to ``brain.db``.
``NOCKBRAIN_STORE=json`` always forces JSON: the reversible kill-switch, same
doctrine as NOCKBRAIN_LIVE_RECALL.

This module is reachable from the recall hook, so it stays Python-3.9
importable and stdlib-only (``sqlite3`` is stdlib; FTS5/sqlite-vec are later
optional accelerators, never required).
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from _facts import filter_valid_facts, load_facts as _load_facts_json
from _store import FILE_MODE, secure_copyfile, secure_mkdir, secure_write_json

DB_FILENAME = "brain.db"
MARKER_FILENAME = "store-v2"
ENV_VAR = "NOCKBRAIN_STORE"
SCHEMA_VERSION = 1
DEGRADATION_LOG = "recall-degradations.jsonl"


def _record_degradation(db_path: Path, reason: str) -> None:
    """Append one degradation event next to the store, best-effort.

    A degraded read (missing/broken db -> empty recall) is emitted to stderr,
    but stderr nobody watches is still a silent outage, so every degradation
    also lands in a small JSONL that nockbrain-health.py aggregates into a
    flag. This must NEVER raise or block the hook: any failure to record is
    swallowed (the recall result is already degraded; making it worse to log
    that fact would invert the priority)."""
    try:
        log_path = Path(db_path).parent / DEGRADATION_LOG
        line = json.dumps({
            "at": datetime.now(timezone.utc).isoformat(),
            "db": str(db_path),
            "reason": reason,
        })
        with open(log_path, "a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        log_path.chmod(FILE_MODE)
    except Exception:  # nosec B110 - deliberate: the recall result is already
        # degraded; raising while trying to LOG that fact would invert the
        # priority and break the hook's never-block contract.
        pass

# Modeled scalar columns. Everything else (unknown fields, explicit nulls,
# non-scalar values in a modeled slot) rides the `extra` JSON column, which is
# what makes the round-trip lossless for facts this schema has never heard of.
FACT_COLUMNS = (
    "id", "kind", "content", "status", "confidence", "source", "source_date",
    "valid_at", "invalid_at", "superseded_by", "superseded_at",
    "supersession_reason", "session", "session_anchor", "created_at",
    "last_seen_at",
)
# Structured fields stored as canonical JSON text in their own columns.
JSON_COLUMNS = ("evidence", "attestation")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS facts (
  id TEXT PRIMARY KEY, kind TEXT, content TEXT, status TEXT, confidence REAL,
  source TEXT, source_date TEXT, valid_at TEXT, invalid_at TEXT,
  superseded_by TEXT, superseded_at TEXT, supersession_reason TEXT,
  session TEXT, session_anchor TEXT, created_at TEXT, last_seen_at TEXT,
  evidence TEXT, attestation TEXT, extra TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS facts_status_kind ON facts(status, kind);
CREATE INDEX IF NOT EXISTS facts_superseded_by ON facts(superseded_by);
-- Ship in the schema, stay unpopulated until P5: insights and embeddings are
-- derived artifacts whose live sources remain insights.json / embeddings.npz.
CREATE TABLE IF NOT EXISTS insights (id TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS embeddings (
  fact_id TEXT PRIMARY KEY REFERENCES facts(id),
  model_id TEXT NOT NULL, dim INTEGER NOT NULL, vector BLOB NOT NULL
);
"""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _column_conforms(name: str, value: Any) -> bool:
    """A value may occupy its modeled column only when SQLite's type affinity
    would hand it back unchanged: floats in the REAL column (``confidence``),
    strings in TEXT columns. An int would be coerced (1 -> 1.0 under REAL,
    7 -> '7' under TEXT), so ints, like bools, None, and structures, ride
    ``extra`` to keep the round-trip type-exact."""
    if name == "confidence":
        return isinstance(value, float) and not isinstance(value, bool)
    return isinstance(value, str)


def _fact_to_row(fact: "dict[str, Any]") -> "tuple[Any, ...]":
    """Split a fact into modeled columns + JSON columns + the extra spill.

    Non-conforming values (see ``_column_conforms``) and unknown keys go to
    ``extra`` so a reload reproduces the original dict exactly: keys the fact
    never had are never fabricated, types never drift."""
    columns: "dict[str, Any]" = {}
    extra: "dict[str, Any]" = {}
    for key, value in fact.items():
        if key in JSON_COLUMNS:
            columns[key] = _canonical_json(value)
        elif key in FACT_COLUMNS and _column_conforms(key, value):
            columns[key] = value
        else:
            extra[key] = value
    row = [columns.get(name) for name in FACT_COLUMNS]
    row.extend(columns.get(name) for name in JSON_COLUMNS)
    row.append(_canonical_json(extra))
    return tuple(row)


def _row_to_fact(row: "tuple[Any, ...]") -> "dict[str, Any]":
    fact: "dict[str, Any]" = {}
    offset = len(FACT_COLUMNS)
    for i, name in enumerate(FACT_COLUMNS):
        if row[i] is not None:
            fact[name] = row[i]
    for j, name in enumerate(JSON_COLUMNS):
        if row[offset + j] is not None:
            fact[name] = json.loads(row[offset + j])
    fact.update(json.loads(row[offset + len(JSON_COLUMNS)]))
    return fact


class JsonStore:
    """Today's facts.json behavior, unchanged, behind the contract."""

    kind = "json"

    def __init__(self, facts_path: Path):
        self.facts_path = Path(facts_path)
        # The verify cache stats this file to decide freshness.
        self.freshness_path = self.facts_path

    def load_facts(self, required_fields: "set[str] | None" = None) -> "list[dict]":
        def _on_unreadable(reason: str) -> None:
            _record_degradation(self.facts_path, f"json-error: {reason}")

        return _load_facts_json(
            self.facts_path,
            required_fields=required_fields,
            on_unreadable=_on_unreadable,
        )

    def replace_all(self, facts: "list[dict]") -> None:
        secure_write_json(self.facts_path, facts, indent=2, default=str)

    def snapshot(self, dest: Path) -> None:
        secure_copyfile(self.facts_path, Path(dest))

    def export_facts_json(self, dest: Path) -> None:
        dest = Path(dest)
        if dest.resolve() == self.facts_path.resolve():
            return
        secure_copyfile(self.facts_path, dest)

    def describe(self) -> str:
        return f"json:{self.facts_path}"


class SqliteStore:
    """The same facts in one WAL-mode SQLite file, value-identically."""

    kind = "sqlite"

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.freshness_path = self.db_path

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(str(self.db_path), timeout=2.0)
        # Degrade to the hook's fail-open-to-empty contract instead of hanging.
        con.execute("PRAGMA busy_timeout=2000")
        return con

    def _chmod_files(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            sidecar = Path(str(self.db_path) + suffix)
            if sidecar.exists():
                sidecar.chmod(FILE_MODE)

    def create(self, store_uuid: str = "") -> None:
        secure_mkdir(self.db_path.parent)
        con = self._connect()
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(_SCHEMA)
            con.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            if store_uuid:
                con.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('store_uuid', ?)",
                    (store_uuid,),
                )
            con.commit()
        finally:
            con.close()
        self._chmod_files()

    def meta(self) -> "dict[str, str]":
        con = self._connect()
        try:
            return dict(con.execute("SELECT key, value FROM meta"))
        finally:
            con.close()

    def set_meta(self, key: str, value: str) -> None:
        con = self._connect()
        try:
            con.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
            con.commit()
        finally:
            con.close()

    def load_facts(self, required_fields: "set[str] | None" = None) -> "list[dict]":
        # A read must never create an empty brain.db (sqlite3.connect would),
        # and a broken db degrades to empty (the hook's fail-open contract).
        # Every degraded read is also recorded for health aggregation.
        if not self.db_path.exists():
            _record_degradation(self.db_path, "db-missing")
            return []
        columns = ", ".join(FACT_COLUMNS + JSON_COLUMNS + ("extra",))
        con = self._connect()
        try:
            # Column list is built from hardcoded tuples above, never
            # external input (bandit suppression on the statement line).
            rows = con.execute(
                f"SELECT {columns} FROM facts ORDER BY rowid"  # nosec B608
            ).fetchall()
        except sqlite3.Error as exc:
            print(f"{self.db_path}: skipped unreadable sqlite store ({exc})",
                  file=sys.stderr)
            _record_degradation(self.db_path, f"sqlite-error: {exc}")
            return []
        finally:
            con.close()
        facts = [_row_to_fact(row) for row in rows]
        return filter_valid_facts(
            facts, source=str(self.db_path), required_fields=required_fields
        )

    def replace_all(self, facts: "list[dict]") -> None:
        placeholders = ", ".join("?" for _ in range(len(FACT_COLUMNS) + len(JSON_COLUMNS) + 1))
        columns = ", ".join(FACT_COLUMNS + JSON_COLUMNS + ("extra",))
        rows = [_fact_to_row(f) for f in facts if isinstance(f, dict)]
        con = self._connect()
        try:
            with con:  # one transaction: readers never see a half-replaced store
                con.execute("DELETE FROM facts")
                # Column list/placeholders come from hardcoded tuples; all
                # values are bound parameters (bandit suppression inline).
                con.executemany(
                    f"INSERT INTO facts ({columns}) VALUES ({placeholders})",  # nosec B608
                    rows,
                )
        finally:
            con.close()
        self._chmod_files()

    def snapshot(self, dest: Path) -> None:
        dest = Path(dest)
        secure_mkdir(dest.parent)
        con = self._connect()
        try:
            con.execute("VACUUM INTO ?", (str(dest),))
        finally:
            con.close()
        dest.chmod(FILE_MODE)

    def export_facts_json(self, dest: Path) -> None:
        secure_write_json(Path(dest), self.load_facts(), indent=2, default=str)

    def describe(self) -> str:
        return f"sqlite:{self.db_path}"


def resolve_store(facts_path: Path, env: "os._Environ | dict | None" = None):
    """Pick the backend for a store rooted at ``facts_path``'s directory.

    JSON is authoritative by default. SQLite engages only when explicitly
    selected: ``NOCKBRAIN_STORE=sqlite``, or a ``store-v2`` marker file next to
    an existing ``brain.db`` (the deliberate cutover artifact). Setting
    ``NOCKBRAIN_STORE=json`` always forces JSON: instant rollback."""
    env = os.environ if env is None else env
    facts_path = Path(facts_path)
    store_dir = facts_path.parent
    db_path = store_dir / DB_FILENAME
    # Derived artifacts (insights.json, graph.json, …) live next to the
    # store. Keying off the parent directory would load brain.db and serve
    # facts as insights. Only the authoritative facts file (or an
    # explicit brain.db path) may select SQLite.
    if facts_path.name not in ("facts.json", DB_FILENAME):
        return JsonStore(facts_path)
    choice = str(env.get(ENV_VAR, "")).strip().lower()
    if choice == "json":
        return JsonStore(facts_path)
    if choice == "sqlite":
        return SqliteStore(db_path)
    if (store_dir / MARKER_FILENAME).exists() and db_path.exists():
        return SqliteStore(db_path)
    return JsonStore(facts_path)
