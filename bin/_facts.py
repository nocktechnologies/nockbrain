"""Shared fact-store validation and loading helpers."""
# Deferred annotations keep this module importable on Python 3.9 (stock macOS
# /usr/bin/python3): the recall hook resolves plain `python3` from PATH, and
# PEP 604 unions in def signatures are a def-time TypeError before 3.10.
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_FACT_FIELDS = {"id", "kind", "status", "confidence", "content", "source_date", "evidence"}
RECALL_ITEM_FIELDS = {"kind", "status", "confidence", "content", "source_date"}

# The owning agent/source of a fact (gbrain-style per-agent scoping). DELIBERATELY
# NOT in the required-field sets above: it is optional, so a single-brain store
# and every pre-source fact stay valid and read as all-DEFAULT_SOURCE. Add it to
# a fact to scope it; leave it off and the fact belongs to the default brain.
# The standalone release rewrites this line to the value after the marker
# (standalone-store facts always carry an explicit source, so the default is
# inert).
DEFAULT_SOURCE = "local"


def fact_source(fact: Any) -> str:
    """The source/owner of a fact. Missing, blank, or non-string `source`
    defaults to DEFAULT_SOURCE, so backward compatibility is automatic and a
    null source can never read as a distinct scope."""
    if isinstance(fact, dict):
        src = fact.get("source")
        if isinstance(src, str) and src.strip():
            return src.strip()
    return DEFAULT_SOURCE


def malformed_fact_reason(fact: Any, required_fields: set[str] | None = None) -> str:
    if not isinstance(fact, dict):
        return "not an object"
    required = required_fields or REQUIRED_FACT_FIELDS
    missing = sorted(field for field in required if field not in fact)
    if missing:
        return "missing " + ", ".join(missing)
    return ""


def valid_fact(fact: Any, required_fields: set[str] | None = None) -> bool:
    return not malformed_fact_reason(fact, required_fields)


def fill_source_date(fact: Any) -> None:
    """Derive ``source_date`` from ``source_time`` when the v2 payload omitted it.

    Recall ranks and diversity-caps on ``source_date``; claim-authority facts
    carry signed ``source_time`` instead. Filling here keeps the
    signed core untouched: ``source_date`` is not in the v2 payload.
    """
    if not isinstance(fact, dict):
        return
    existing = fact.get("source_date")
    if isinstance(existing, str) and existing.strip():
        return
    source_time = fact.get("source_time")
    if isinstance(source_time, str) and len(source_time) >= 10:
        fact["source_date"] = source_time[:10]


def filter_valid_facts(
    facts: Any,
    *,
    source: str = "facts",
    required_fields: set[str] | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(facts, list):
        print(f"{source}: skipped malformed fact store (expected list)", file=sys.stderr)
        return []

    valid: list[dict[str, Any]] = []
    skipped = 0
    for fact in facts:
        fill_source_date(fact)
        if valid_fact(fact, required_fields):
            valid.append(fact)
        else:
            skipped += 1
    if skipped:
        print(f"{source}: skipped {skipped} malformed fact record(s)", file=sys.stderr)
    return valid


def load_facts(
    path: Path | None,
    *,
    source: str | None = None,
    required_fields: set[str] | None = None,
    on_unreadable: Any = None,
) -> list[dict[str, Any]]:
    if not path or not path.exists():
        return []
    label = source or str(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        # ValueError covers JSONDecodeError and UnicodeDecodeError.
        print(f"{label}: skipped malformed fact store ({exc})", file=sys.stderr)
        if on_unreadable is not None:
            on_unreadable(str(exc))
        return []
    return filter_valid_facts(data, source=label, required_fields=required_fields)


# ── Content-token helpers (shared by dedup + contradiction pairing) ──────────
_CONTENT_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def content_tokens(text: Any) -> frozenset:
    """Case-, punctuation- and whitespace-insensitive token set of a content."""
    if not isinstance(text, str):
        return frozenset()
    return frozenset(t for t in _CONTENT_TOKEN_RE.split(text.lower()) if t)


def jaccard(a: Any, b: Any) -> float:
    """Jaccard similarity of two contents' normalized token sets (0 when either
    side has no tokens)."""
    ta, tb = content_tokens(a), content_tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


# ── Bi-temporal validity (supersede-over-delete with a window) ───────────────
# Facts may carry OPTIONAL window bounds. A fact is "currently valid" iff
# start <= now < end, treating a MISSING bound as open (-inf / +inf).
# v1 operational fields: `valid_at` / `invalid_at`.
# v2 claim-authority fields (signed): `valid_from` / `valid_to`.
# Either pair can close the window; both absent ⇒ always valid so every
# existing fact and caller is unaffected. This lets recall stop surfacing a
# fact as *current* once it has been superseded/expired, while the fact stays
# in the store for historical queries (recoverable via include_superseded).
def _parse_ts(value: Any) -> "datetime | None":
    """Parse an ISO-8601 timestamp; return None on anything unparseable
    (lenient by design: a malformed bound must never break recall)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Normalize to aware UTC so comparisons against an aware `now` never raise.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def fact_currently_valid(fact: Any, now: "datetime | None" = None) -> bool:
    """True if `fact`'s bi-temporal validity window contains `now`.

    Missing/blank/unparseable bounds are treated as open, so a fact without
    these fields is always valid (backward compatible). v1 uses
    ``valid_at``/``invalid_at``; v2 claims use signed ``valid_from``/``valid_to``.
    Either pair can exclude the fact.
    """
    if not isinstance(fact, dict):
        return True
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    for start_field in ("valid_at", "valid_from"):
        start = _parse_ts(fact.get(start_field))
        if start is not None and now < start:
            return False  # not yet in effect
    for end_field in ("invalid_at", "valid_to"):
        end = _parse_ts(fact.get(end_field))
        if end is not None and now >= end:
            return False  # window has closed (superseded/expired)
    return True


# Append-only id logs consulted by rebuild merge so a re-extract cannot
# resurrect a purge, edit, or attested supersession.
TOMBSTONES_FILENAME = "purged-ids.jsonl"
FACT_EDITS_FILENAME = "fact-edits.jsonl"


def load_jsonl_ids(path: Path, field: str) -> set[str]:
    """Collect string ids from a JSONL sidecar.

    Each line is a JSON object (``field`` or ``id``) or a bare id string.
    Missing files and malformed lines are skipped: a rebuild must not die
    because a sidecar is absent.
    """
    ids: set[str] = set()
    path = Path(path)
    if not path.exists():
        return ids
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ids
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            ids.add(line)
            continue
        if isinstance(row, dict):
            value = row.get(field) or row.get("id")
            if value:
                ids.add(str(value))
        elif isinstance(row, str) and row:
            ids.add(row)
    return ids
