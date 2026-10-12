"""Projection readback receipts (S4).

A derived/projection write can silently fail or go stale and nothing notices:
the class of failure that can silently freeze a store's memory for days. The fix
(a readback ledger): every projection write becomes a LEDGER ROW that
is only marked "applied" after the written file is READ BACK and its content
hash matches what was intended. When readback does not match, the row is
"ambiguous": a first-class outcome, never a silent success and never a raise.

Dependency-free and Python-3.9 importable (deferred annotations, no evaluated
PEP 604 unions) so the exporters, including the recall-reachable graph export,
can share it. Receipts append to a projection-receipts.jsonl next to the
store, mirroring recall-degradations.jsonl.
"""
# Deferred annotations keep this importable on Python 3.9 (stock macOS
# /usr/bin/python3): it is reachable from the recall hook via export-graph.
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from _store import FILE_MODE, secure_mkdir, secure_write_text

RECEIPTS_FILENAME = "projection-receipts.jsonl"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _render(content_or_obj: Any, kind: str, json_kwargs: "dict[str, Any]") -> str:
    """The exact text we intend to land on disk. JSON is serialized here (once)
    so the intended hash and the bytes actually written come from one string."""
    if kind == "json":
        return json.dumps(content_or_obj, **json_kwargs)
    if kind == "text":
        if not isinstance(content_or_obj, str):
            raise TypeError("kind='text' needs a str; use kind='json' for objects")
        return content_or_obj
    raise ValueError(f"unknown kind: {kind!r}")


def write_with_receipt(
    path: Path,
    content_or_obj: Any,
    receipts_path: Path,
    *,
    kind: str = "text",
    encoding: str = "utf-8",
    **json_kwargs: Any,
) -> "dict[str, Any]":
    """Write `path`, read it straight back, and append an applied/ambiguous row.

    The write goes through the secure_write_* helpers, so mode bits and parent
    dirs match every other artifact. Then the file is read back and its bytes
    are sha256-compared to what we meant to write: "applied" iff the on-disk
    bytes hash to the intended hash, "ambiguous" otherwise. A readback that
    raises (file vanished, truncated/failed write, unreadable) is ambiguous
    too. The whole point is that a broken projection never passes silently, so
    this never raises on a mismatch; it records one. Returns the receipt row."""
    text = _render(content_or_obj, kind, json_kwargs)
    intended = text.encode(encoding)
    intended_sha = hashlib.sha256(intended).hexdigest()
    try:
        secure_write_text(Path(path), text, encoding=encoding)
        on_disk = Path(path).read_bytes()
        status = "applied" if hashlib.sha256(on_disk).hexdigest() == intended_sha else "ambiguous"
    except OSError:
        status = "ambiguous"
    receipt = {
        "at": _now_iso(),
        "artifact_path": str(path),
        "sha256": intended_sha,
        "bytes": len(intended),
        "status": status,
    }
    append_receipt(receipts_path, receipt)
    return receipt


def append_receipt(receipts_path: Path, receipt: "dict[str, Any]") -> None:
    """Append one receipt row to the JSONL ledger, private-mode like the store."""
    path = Path(receipts_path)
    secure_mkdir(path.parent)
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(receipt) + "\n")
    path.chmod(FILE_MODE)


def load_receipts(receipts_path: Path) -> "list[dict[str, Any]]":
    """Load receipt rows in append order; skip malformed lines (never raise)."""
    path = Path(receipts_path)
    if not path.exists():
        return []
    receipts: "list[dict[str, Any]]" = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Only dict rows: a decoded null / [] / scalar would later crash
        # last_status()'s .get(); a health checker must not die on a
        # malformed artifact (same class as the contradiction-queue guard).
        if isinstance(row, dict):
            receipts.append(row)
    return receipts


def last_status(receipts: "list[dict[str, Any]]", artifact_path: Any) -> str:
    """Status of the newest receipt for `artifact_path` (append order wins), or
    "" when the ledger has never recorded that artifact."""
    target = str(artifact_path)
    status = ""
    for receipt in receipts:
        if receipt.get("artifact_path") == target:
            status = receipt.get("status", "")
    return status
