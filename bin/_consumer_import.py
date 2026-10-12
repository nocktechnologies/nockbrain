"""Read explicitly selected notes into reviewable, unsigned candidates."""
from __future__ import annotations

import hashlib
import importlib.util
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from _classify import authority_fact_allowed, classify_bullet
from _consumer_store import (ConsumerError, MAX_CANDIDATES, MAX_SOURCES,
                             SOURCE_LIMIT, canonical_bytes, read_regular, _json)
from _scrub import is_structural_noise, scrub_secrets

TOTAL_SOURCE_LIMIT = 32 * 1024 * 1024

# A standalone store has no roster of named authorities: only the literal `user`
# role (JSONL) or the generic role words (markdown) carry authority, so
# "Alice decided" and any other personal name read identically. The standalone
# hook's recall classifier uses the same empty roster.
CUSTOMER_AUTHORITY_NAMES: frozenset = frozenset()

# Generic ingest counters a user can act on; each is reported when the
# ingest module in use produces it (the harness-wrapper pair arrives with a
# sibling change), so this tuple may run ahead of ingest without effect.
CUSTOMER_INGEST_STATS = ("lines_read", "events_written", "sidechain_excluded",
                         "denied_paths", "denied_tools", "denied_endpoints",
                         "denied_results", "denied_result_paths",
                         "denied_result_endpoints", "harness_wrappers_dropped",
                         "system_reminders_stripped")
# Transport counters that cannot move on the standalone path: frames are blanked
# before ingest and no transport is ever installed, so no tool result can be
# promoted to a user turn. One moving is a bug, so the import fails and names
# it. Any other counter ingest reports is generic bookkeeping and is simply
# not surfaced.
TRANSPORT_INGEST_STATS = ("channel_wrappers_unwrapped", "channel_wrappers_dropped",
                      "voice_envelopes_seen_allowlist_unset",
                      "transcribe_results_promoted", "transcribe_results_dropped")
# Same opening as _channel_frame.CHANNEL_FRAME_RE's tag (`<channel\s`), so a
# frame the grammar would accept can never slip past as plain text.
_FRAME_RE = re.compile(r"<channel\s")


def _sibling(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, BIN_DIR / filename)
    if spec is None or spec.loader is None:
        raise ConsumerError("import adapter unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ingest = _sibling("_consumer_ingest_jsonl", "ingest-jsonl.py")


def _source_stamp(info: Any) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_uid)


def _selected_regular(path: Path, stamp: tuple[int, ...]) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ConsumerError("source changed during selection") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            _source_stamp(info) != stamp):
        raise ConsumerError("source changed during selection")


def _safe_source(path: Path) -> tuple[Path, tuple[int, ...]]:
    if not path.is_absolute():
        raise ConsumerError("source path must be absolute")
    try:
        selected = path.lstat()
        if not stat.S_ISREG(selected.st_mode) or selected.st_nlink != 1:
            raise ConsumerError("unsafe regular file")
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ConsumerError("source path cannot be resolved") from exc
    stamp = _source_stamp(selected)
    # Resolve may cross a stable parent alias, but must never exchange the
    # explicitly selected leaf (including a symlink swapped in mid-resolution).
    _selected_regular(path, stamp)
    _selected_regular(resolved, stamp)
    for candidate in (path, resolved):
        value = str(candidate)
        parts = candidate.parts
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ConsumerError("invalid source path encoding") from exc
        if (len(value) > 1024 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
                or "\\" in value or any(part.casefold() in {".ssh", ".gnupg"} for part in parts)
                or candidate.name.casefold().startswith("signing-key")
                or _ingest._matches_any(value, _ingest.DEFAULT_PATH_DENYLIST)):
            raise ConsumerError("source path is denied")
    return resolved, stamp


def _mtime_timestamp(mtime_ns: int) -> str:
    seconds, nanoseconds = divmod(mtime_ns, 1_000_000_000)
    return (datetime.fromtimestamp(seconds, timezone.utc) +
            timedelta(microseconds=nanoseconds // 1000)).isoformat()


def _source_timestamp(value: Any, fallback: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return fallback
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return fallback


def _candidate(manifest: dict, kind: str, content: str, confidence: float,
               actor: str, path: str, sha256: str, line: int, event_id: str,
               timestamp: str) -> dict:
    store_id = manifest["store_id"]
    return {
        "id": "customer-" + hashlib.sha256(canonical_bytes([store_id, kind, content])).hexdigest(),
        "kind": kind, "content": content, "confidence": confidence,
        "scope": "global", "status": "current", "source": "customer:" + store_id,
        "source_file": Path(path).name, "source_date": timestamp[:10],
        "created_at": timestamp, "subject": actor,
        "evidence": [{"store_id": store_id, "key_id": manifest["key_id"],
                      "sha256": sha256, "path": path, "line": line, "event_id": event_id}],
    }


def _append(candidates: list[dict], by_id: dict[str, dict], manifest: dict,
            content: str, actor: str, path: str, sha256: str, line: int,
            event_id: str, timestamp: str, stats: dict) -> None:
    content = content.strip()
    try:
        content.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ConsumerError("invalid source content encoding") from exc
    if not content or is_structural_noise(content):
        return
    result = classify_bullet(content, CUSTOMER_AUTHORITY_NAMES)
    if result is None:
        return
    kind, confidence = result
    if not authority_fact_allowed(kind, content, actor=actor, names=CUSTOMER_AUTHORITY_NAMES):
        return
    if len(content) > 1500:
        stats["overlong_skipped"] += 1
        return
    candidate = _candidate(manifest, kind, content, confidence, actor, path,
                           sha256, line, event_id, timestamp)
    existing = by_id.get(candidate["id"])
    if existing is not None:
        evidence = candidate["evidence"][0]
        if evidence not in existing["evidence"]:
            if len(existing["evidence"]) >= 1000:
                raise ConsumerError("too much candidate evidence")
            existing["evidence"].append(evidence)
        return
    if len(candidates) >= MAX_CANDIDATES:
        raise ConsumerError("too many candidates")
    candidates.append(candidate)
    by_id[candidate["id"]] = candidate


def _valid_message(raw: dict) -> tuple[list[int], bool]:
    """Validate text surfaces before line_events can coerce malformed shapes."""
    line_type = raw.get("type")
    if line_type not in {"user", "assistant"}:
        return [], False
    message = raw.get("message")
    if not isinstance(message, dict):
        raise ConsumerError("invalid JSONL message")
    role = message.get("role", line_type)
    if role != line_type:
        raise ConsumerError("JSONL message role mismatch")
    content = message.get("content")
    if isinstance(content, str):
        return ([0] if content else []), False
    if not isinstance(content, list):
        raise ConsumerError("invalid JSONL content")
    text_indices = []
    has_tool_result = False
    for index, part in enumerate(content):
        if not isinstance(part, dict):
            raise ConsumerError("invalid JSONL content part")
        part_type = part.get("type", "text")
        if not isinstance(part_type, str):
            raise ConsumerError("invalid JSONL content part")
        if part_type == "text":
            if not isinstance(part.get("text"), str):
                raise ConsumerError("invalid JSONL text part")
            if part["text"]:
                text_indices.append(index)
        elif part_type == "tool_use":
            if (not isinstance(part.get("name"), str) or
                    not isinstance(part.get("id", ""), str) or
                    not isinstance(part.get("input", {}), dict)):
                raise ConsumerError("invalid JSONL tool use")
        elif part_type == "tool_result":
            has_tool_result = True
            if not isinstance(part.get("tool_use_id", ""), str):
                raise ConsumerError("invalid JSONL tool result")
    return text_indices, has_tool_result


def _without_channel_frames(raw: dict, stats: dict) -> dict:
    """Blank channel-framed text (``<channel …>`` transport receipts).

    A frame is another channel's relay, not the user's own turn, whatever
    sender its envelope claims, so it can never become a candidate, let alone
    user authority. Blanking (rather than removing) keeps part indices stable
    for evidence anchors. Runs after `_valid_message`, so shapes are known.
    """
    message = raw["message"]
    content = message["content"]
    if isinstance(content, str):
        if not _FRAME_RE.match(content.lstrip()):
            return raw
        stats["channel_frames_skipped"] += 1
        return dict(raw, message=dict(message, content=""))
    parts = []
    for part in content:
        if part.get("type", "text") == "text" and _FRAME_RE.match(part["text"].lstrip()):
            stats["channel_frames_skipped"] += 1
            part = dict(part, text="")
        parts.append(part)
    return dict(raw, message=dict(message, content=parts))


def collect_candidates(sources: list[Path], format: str, manifest: dict) -> tuple[list[dict], list[dict], dict]:
    """Capture bounded explicit sources and return deterministic proposal inputs."""
    if format not in {"markdown", "claude-jsonl"}:
        raise ConsumerError("unsupported source format")
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        raise ConsumerError("invalid source count")
    if (not isinstance(manifest, dict) or not isinstance(manifest.get("store_id"), str)
            or not isinstance(manifest.get("key_id"), str)):
        raise ConsumerError("invalid store manifest")
    candidates: list[dict] = []
    by_id: dict[str, dict] = {}
    receipts: list[dict] = []
    stats = {"files": 0, "candidates": 0, "overlong_skipped": 0,
             "secrets_redacted": 0}
    ingest_stats = _ingest.new_stats()
    if format == "claude-jsonl":
        stats.update({key: 0 for key in CUSTOMER_INGEST_STATS if key in ingest_stats},
                     channel_frames_skipped=0)
    seen_paths: set[Path] = set()
    seen_files: set[tuple[int, int]] = set()
    total = 0
    for source in sources:
        selected_path = Path(source)
        path, selected_stamp = _safe_source(selected_path)
        try:
            _selected_regular(selected_path, selected_stamp)
            before = path.lstat()
            if _source_stamp(before) != selected_stamp:
                raise ConsumerError("source changed during selection")
            if path in seen_paths or (before.st_dev, before.st_ino) in seen_files:
                raise ConsumerError("duplicate source file")
            if before.st_size > SOURCE_LIMIT or total + before.st_size > TOTAL_SOURCE_LIMIT:
                raise ConsumerError("source exceeds size limit")
            data = read_regular(path, min(SOURCE_LIMIT, TOTAL_SOURCE_LIMIT - total))
            after = path.lstat()
        except OSError as exc:
            raise ConsumerError("cannot read source file") from exc
        _selected_regular(selected_path, selected_stamp)
        if _source_stamp(after) != selected_stamp:
            raise ConsumerError("source changed during read")
        seen_paths.add(path)
        seen_files.add((before.st_dev, before.st_ino))
        total += len(data)
        source_hash = hashlib.sha256(data).hexdigest()
        receipt_path, path_redactions = scrub_secrets(str(path))
        stats["secrets_redacted"] += path_redactions
        if (not receipt_path.startswith("/") or len(receipt_path) > 1024 or
                any(part in {"", ".", ".."} for part in receipt_path[1:].split("/"))):
            raise ConsumerError("unsafe source metadata")
        receipts.append({"path": receipt_path, "sha256": source_hash, "format": format})
        fallback = _mtime_timestamp(before.st_mtime_ns)
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ConsumerError("source is not UTF-8") from exc
        if format == "markdown":
            for line_number, line in enumerate(text.splitlines(), 1):
                if not line.startswith("- "):
                    continue
                scrubbed, count = scrub_secrets(line[2:])
                stats["secrets_redacted"] += count
                _append(candidates, by_id, manifest, scrubbed, "user", receipt_path,
                        source_hash, line_number, f"{source_hash}:{line_number}:0", fallback, stats)
        else:
            denied_tool_ids: set[str] = set()
            for line_number, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                ingest_stats["lines_read"] += 1
                try:
                    raw = _json(line.encode("utf-8"))
                except ConsumerError as exc:
                    raise ConsumerError("invalid JSONL line") from exc
                if not isinstance(raw, dict):
                    raise ConsumerError("JSONL line must be an object")
                if not isinstance(raw.get("type"), str):
                    raise ConsumerError("invalid JSONL event type")
                if "isSidechain" in raw and not isinstance(raw["isSidechain"], bool):
                    raise ConsumerError("invalid JSONL sidechain flag")
                text_indices, has_tool_result = _valid_message(raw)
                if text_indices:
                    raw = _without_channel_frames(raw, stats)
                    text_indices, has_tool_result = _valid_message(raw)
                events = _ingest.line_events(raw, path, line_number, ingest_stats,
                                             include_sidechain=False,
                                             denied_tool_use_ids=denied_tool_ids)
                ingest_stats["events_written"] += len(events)
                text_events = [event for event in events if event["surface"] == "text"
                               and event["kind"] == "message"]
                # Ingest may drop a part (harness wrappers) or rewrite it (system
                # reminders stripped), so events are aligned to parts by the part
                # index ingest stamps on each one, never by count or order.
                indices = [event.get("metadata", {}).get("part_index") for event in text_events]
                allowed = set() if raw.get("isSidechain") else set(text_indices)
                if len(set(indices)) != len(indices) or any(
                        type(index) is not int or index not in allowed for index in indices):
                    raise ConsumerError("invalid JSONL text events")
                if has_tool_result:
                    continue
                timestamp = _source_timestamp(raw.get("timestamp"), fallback)
                for part_index, event in zip(indices, text_events):
                    # The ingest event's actor, not the line type: only exact
                    # `user` passes the authority gate in _append.
                    _append(candidates, by_id, manifest, event["content"],
                            event["actor"], receipt_path, source_hash, line_number,
                            f"{source_hash}:{line_number}:{part_index}", timestamp, stats)
        stats["files"] += 1
    stats["secrets_redacted"] += ingest_stats.get("secrets_redacted", 0)
    for key in CUSTOMER_INGEST_STATS:
        if key in stats:
            stats[key] = ingest_stats[key]
    for key in TRANSPORT_INGEST_STATS:
        if ingest_stats.get(key):
            raise ConsumerError("transport counter moved: " + key)
    stats["candidates"] = len(candidates)
    return candidates, receipts, stats
