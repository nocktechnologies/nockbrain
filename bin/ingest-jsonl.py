#!/usr/bin/env python3
"""Ingest raw Claude Code JSONL transcripts into sanitized evidence events.

This is the v2 entry point before fact extraction. It preserves source anchors
and treats tool_use inputs as first-class evidence, while denying private paths,
private tools/endpoints, and scrubbing secrets before events are returned or
written. Harness text recorded in the user role (compaction summaries, system
reminders, relayed agent messages) is fenced out.

A ``<channel`` user turn is a transport receipt, not conversation: only a
transport knows its grammar. A deployment's transport (channel-relay frames,
promotion of transcribed tool results) is a separate module this file never
names; the CLI loads one by path (``--transport``) and the standalone release
ships none. Without a transport every channel turn is dropped and counted
(``channel_wrappers_dropped``).

Usage:
    python3 bin/ingest-jsonl.py ~/.claude/projects/.../session.jsonl
    python3 bin/ingest-jsonl.py --output events.jsonl session.jsonl
    python3 bin/ingest-jsonl.py --transport bin/<transport>.py session.jsonl
"""
# Deferred annotations keep this importable on Python 3.9 (stock macOS
# /usr/bin/python3, which non-interactive shells resolve): PEP 604 unions
# in signatures are a def-time TypeError before 3.10.
from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from _scrub import scrub_secrets
from _store import secure_write_text
# The shared frame grammar (the purge tool and transport modules use it too);
# the standalone importer pins its own frame prefix against it through here.
from _channel_frame import CHANNEL_FRAME_RE  # noqa: F401

DEFAULT_PATH_DENYLIST = [
    "agents/*/private/**",
    "*/agents/*/private/**",
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "*token*",
    "**/*token*",
    "*secret*",
    "**/*secret*",
    "credentials*",
    "**/credentials*",
    "id_rsa*",
    "**/id_rsa*",
    "*.pem",
    "**/*.pem",
]

# Private agent tools never become evidence. Generic shapes on purpose, and
# segment-anchored: a tool whose name carries a "diary" or "private" segment
# at a "_" or "-" boundary -- leading, inner, trailing or the bare word -- is
# denied whatever server prefix precedes it (``srv_private_notes``,
# ``mcp__srv__srv_diary_write``, ``mcp__nock-diary__append``,
# ``private-notes``, ``read_diary``, ``private``); a mere substring
# (``privateer_scan``) or a camelCase run (``readDiary``) is not a boundary.
# Privacy-first by design: a third-party tool such as ``list_private_repos``
# is denied too, and its paired result with it.
DEFAULT_TOOL_DENYLIST = [
    "diary", "diary[-_]*", "*[-_]diary", "*[-_]diary[-_]*",
    "private", "private[-_]*", "*[-_]private", "*[-_]private[-_]*",
]

DEFAULT_ENDPOINT_DENYLIST = [
    "*/api/brain/diary/*",
    "*/api/brain/private/*",
]


def new_stats() -> dict[str, int]:
    return {
        "lines_read": 0,
        "events_written": 0,
        "sidechain_excluded": 0,
        "denied_paths": 0,
        "denied_tools": 0,
        "denied_endpoints": 0,
        "denied_results": 0,
        "denied_result_paths": 0,
        "denied_result_endpoints": 0,
        "secrets_redacted": 0,
        "malformed_lines": 0,
        "channel_wrappers_unwrapped": 0,
        "channel_wrappers_dropped": 0,
        "harness_wrappers_dropped": 0,
        "harness_wrappers_truncated": 0,
        "system_reminders_stripped": 0,
        "voice_envelopes_seen_allowlist_unset": 0,
        "transcribe_results_promoted": 0,
        "transcribe_results_dropped": 0,
    }


# Harness text that Claude Code records in the user role but the user never typed:
# compaction summaries, system reminders, inter-session agent messages. Left
# in, they were distilled into "facts" quoting the harness back at the model.
# Whole-part drops: compaction summaries, and the brief a parent session
# hands a side session (another agent's words, not the user's, which were
# minted as decisions before this fence covered them).
HARNESS_WRAPPER_PREFIXES = (
    "This session is being continued",
    "Background (from the session that started this one)",
)
# From one of these markers to the end of the part is harness output: the
# agent-message lead-in, the block and the explanatory note that follows it,
# an "=== AGENT MESSAGE" paste whose body runs to the end, a background-task
# completion notice, or a side-sessions event. Typed text that happens to
# come before the first marker is kept as the user's turn.
HARNESS_WRAPPER_MARKERS = (
    "<agent-message",
    "=== AGENT MESSAGE",
    "Another Claude session sent a message",
    "<task-notification>",
    "<side-sessions-event>",
)
# System reminders are different: Claude Code appends them to the SAME string
# as the typed prompt (in practice most reminder-bearing parts also hold the
# user's prompt), so complete blocks are stripped and the rest kept.
SYSTEM_REMINDER_BLOCK_RE = re.compile(r"<system-reminder>.*?</system-reminder>", re.DOTALL)


def strip_system_reminders(text: str) -> tuple[str, bool]:
    """Remove complete ``<system-reminder>…</system-reminder>`` blocks.

    Returns the remaining text and whether anything was stripped. An opener
    with no closing tag is left in place: harness reminders always close, so
    a bare tag is a typed prompt talking about reminders (as this repo's do).
    """
    stripped, count = SYSTEM_REMINDER_BLOCK_RE.subn("", text)
    if not count:
        return text, False
    return stripped.strip(), True


def fence_harness_text(raw: dict[str, Any], text: str, stats: dict[str, int]) -> str | None:
    """Return the human text of a non-channel user-role part, or None to drop it.

    Order matters: record flags (``isCompactSummary`` / ``isMeta`` true) drop
    the part outright; then reminders are stripped so their bodies can neither
    hide a continuation summary nor, by quoting a marker, condemn the prompt
    around them; then the leading-prefix rule drops the part; then the first
    marker truncates the part, keeping any typed text before it.
    """
    if raw.get("isCompactSummary") is True or raw.get("isMeta") is True:
        stats["harness_wrappers_dropped"] += 1
        return None
    text, stripped = strip_system_reminders(text)
    if stripped:
        stats["system_reminders_stripped"] += 1
    if not text or text.lstrip().startswith(HARNESS_WRAPPER_PREFIXES):
        stats["harness_wrappers_dropped"] += 1
        return None
    cuts = [index for index in (text.find(marker) for marker in HARNESS_WRAPPER_MARKERS) if index != -1]
    if cuts:
        text = text[:min(cuts)].strip()
        if not text:
            stats["harness_wrappers_dropped"] += 1
            return None
        stats["harness_wrappers_truncated"] += 1
    return text


def normalize_parts(message: dict[str, Any]) -> list[dict[str, Any]]:
    content = message.get("content", "")
    if isinstance(content, list):
        return content
    return [{"type": "text", "text": content or ""}]


def json_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _matches_any(value: str, patterns: list[str]) -> bool:
    cleaned = value.strip().strip("'\"")
    candidates = {cleaned, cleaned.lstrip("/"), cleaned.removeprefix("./"), Path(cleaned).name}
    return any(
        fnmatch.fnmatch(candidate.casefold(), pattern.casefold())
        for candidate in candidates
        for pattern in patterns
    )


def extract_candidate_paths(value: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, inner in value.items():
            if key in {"file_path", "path", "filename"} and isinstance(inner, str):
                paths.append(inner)
            paths.extend(extract_candidate_paths(inner))
    elif isinstance(value, list):
        for item in value:
            paths.extend(extract_candidate_paths(item))
    elif isinstance(value, str):
        # Pull obvious absolute or repo-relative file paths out of shell text.
        paths.extend(re.findall(r"(?:/[\w@%+=:,./-]+|agents/[\w@%+=:,./-]+)", value))
        paths.extend(re.findall(r"(?<![\w/.-])(?:\./)?\.env(?:\.[\w.-]+)?\b", value))
    return paths


def denied_by_path(value: Any, patterns: list[str] | None = None) -> bool:
    denylist = patterns or DEFAULT_PATH_DENYLIST
    return any(_matches_any(path, denylist) for path in extract_candidate_paths(value))


def denied_by_tool(tool_name: str, patterns: list[str] | None = None) -> bool:
    denylist = patterns or DEFAULT_TOOL_DENYLIST
    return _matches_any(tool_name, denylist)


def denied_by_endpoint(value: Any, patterns: list[str] | None = None) -> bool:
    denylist = patterns or DEFAULT_ENDPOINT_DENYLIST
    text = json_text(value)
    candidates = re.findall(r"https?://[^\s'\"<>]+|/api/[A-Za-z0-9_./-]+", text)
    return any(_matches_any(candidate, denylist) for candidate in candidates)


def event_source(path: Path, line_number: int, raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "adapter": "claude-jsonl",
        "path": str(path),
        "line": line_number,
        "session_id": raw.get("sessionId", ""),
        "timestamp": raw.get("timestamp", ""),
    }


def make_event(
    path: Path,
    line_number: int,
    raw: dict[str, Any],
    actor: str,
    surface: str,
    kind: str,
    content: str,
    metadata: dict[str, Any] | None = None,
    stats: dict[str, int] | None = None,
) -> dict[str, Any]:
    scrubbed, redactions = scrub_secrets(content)
    if stats is not None:
        stats["secrets_redacted"] += redactions
    return {
        "id": f"{raw.get('uuid', '')}:{line_number}:{surface}:{kind}",
        "source": event_source(path, line_number, raw),
        "actor": actor,
        "surface": surface,
        "kind": kind,
        "content": scrubbed,
        "metadata": metadata or {},
        "privacy": {
            "scrubbed": redactions > 0,
            "excluded": False,
            "policy_version": "v1",
        },
    }


def line_events(
    raw: dict[str, Any],
    path: Path,
    line_number: int,
    stats: dict[str, int],
    include_sidechain: bool = False,
    denied_tool_use_ids: set[str] | None = None,
    transport: Any = None,
) -> list[dict[str, Any]]:
    """Events for one JSONL record. ``transport`` is one file's transport
    state (``Transport()`` from the module ``--transport`` names) or None."""
    if raw.get("isSidechain") and not include_sidechain:
        stats["sidechain_excluded"] += 1
        return []

    line_type = raw.get("type", "")
    events: list[dict[str, Any]] = []

    if line_type in {"user", "assistant"}:
        message = raw.get("message", {}) if isinstance(raw.get("message"), dict) else {}
        actor = message.get("role") or line_type
        for index, part in enumerate(normalize_parts(message)):
            part_type = part.get("type", "text")
            if part_type == "text":
                text = json_text(part.get("text", ""))
                event_actor = actor
                is_channel_turn = False
                if line_type == "user" and actor == "user":
                    # A harness reminder may precede the envelope, so decide
                    # "channel turn" on the reminder-stripped text. Channel
                    # envelopes arrive with isMeta set and keep their own
                    # grammar; everything else goes through the harness fence.
                    reminder_free, reminder_stripped = strip_system_reminders(text)
                    is_channel_turn = reminder_free.lstrip().startswith("<channel ")
                    if is_channel_turn:
                        text = reminder_free
                        if reminder_stripped:
                            # The fence path counts its own strips inside
                            # fence_harness_text; count the channel path too.
                            stats["system_reminders_stripped"] += 1
                    else:
                        fenced = fence_harness_text(raw, text, stats)
                        if fenced is None:
                            continue
                        text = fenced
                if is_channel_turn:
                    # Transport, not conversation: only a transport knows the
                    # frame grammar (which channel is the user, which is a
                    # relay); without one the turn is dropped, never kept as
                    # the user's words.
                    unwrapped = transport.user_turn(raw, text, stats) if transport is not None else None
                    if unwrapped is None:
                        stats["channel_wrappers_dropped"] += 1
                        continue
                    text, event_actor = unwrapped
                    stats["channel_wrappers_unwrapped"] += 1
                if text:
                    # The content-part index (0 for string content) lets a
                    # consumer align text events to parts after drops/rewrites.
                    events.append(
                        make_event(path, line_number, raw, event_actor, "text", "message", text,
                                   metadata={"part_index": index}, stats=stats)
                    )
            elif part_type == "tool_use":
                tool_name = part.get("name", "")
                tool_input = part.get("input", {})
                tool_use_id = part.get("id", "")
                if denied_by_path(tool_input):
                    stats["denied_paths"] += 1
                    if tool_use_id and denied_tool_use_ids is not None:
                        denied_tool_use_ids.add(tool_use_id)
                    continue
                if denied_by_tool(tool_name):
                    stats["denied_tools"] += 1
                    if tool_use_id and denied_tool_use_ids is not None:
                        denied_tool_use_ids.add(tool_use_id)
                    continue
                if denied_by_endpoint(tool_input):
                    stats["denied_endpoints"] += 1
                    if tool_use_id and denied_tool_use_ids is not None:
                        denied_tool_use_ids.add(tool_use_id)
                    continue
                if transport is not None:
                    # Only a call that passed every denylist can be remembered
                    # (a denied call's result is denied with it, above).
                    transport.tool_call(raw, tool_name, tool_input, tool_use_id)
                events.append(
                    make_event(
                        path,
                        line_number,
                        raw,
                        "assistant",
                        "tool_use.input",
                        "tool_call",
                        json_text(tool_input),
                        metadata={
                            "tool_name": tool_name,
                            "tool_use_id": part.get("id", ""),
                            "is_sidechain": bool(raw.get("isSidechain")),
                        },
                        stats=stats,
                    )
                )
            elif part_type == "tool_result":
                tool_use_id = part.get("tool_use_id", "")
                if denied_tool_use_ids is not None and tool_use_id in denied_tool_use_ids:
                    stats["denied_results"] += 1
                    continue
                # A transport may claim this result as a user message (e.g.
                # promoting a transcription result); every other result stays
                # non-authoritative tool output.
                claim = transport.claim_tool_result(raw, part, stats) if transport is not None else None
                if claim is False:
                    continue
                if claim:
                    content, claim_metadata, claim_key = claim
                else:
                    content = json_text(part.get("content", ""))
                denied_result = False
                if denied_by_path(content):
                    stats["denied_result_paths"] += 1
                    denied_result = True
                if denied_by_endpoint(content):
                    stats["denied_result_endpoints"] += 1
                    denied_result = True
                if denied_result:
                    stats["denied_results"] += 1
                    if claim:
                        transport.dropped_tool_result(stats)
                    continue
                metadata = {
                    "tool_use_id": part.get("tool_use_id", ""),
                    "is_sidechain": bool(raw.get("isSidechain")),
                }
                if claim:
                    metadata.update(claim_metadata)
                events.append(
                    make_event(
                        path,
                        line_number,
                        raw,
                        "user" if claim else "tool",
                        "text" if claim else "tool_result.content",
                        "message" if claim else "tool_result",
                        content,
                        metadata=metadata,
                        stats=stats,
                    )
                )
                if claim:
                    transport.promoted_tool_result(claim_key, stats)

    elif line_type == "system" and raw.get("compactMetadata"):
        events.append(
            make_event(
                path,
                line_number,
                raw,
                "system",
                "system",
                "compaction",
                json_text(raw.get("compactMetadata", {})),
                metadata={"compact_boundary": True},
                stats=stats,
            )
        )

    elif line_type == "pr-link":
        events.append(
            make_event(
                path,
                line_number,
                raw,
                "system",
                "pr-link",
                "provenance",
                json_text({k: raw.get(k) for k in ("prNumber", "prRepository", "prUrl")}),
                stats=stats,
            )
        )

    return events


# A deployment installs its transport factory here (the CLI does, from
# --transport) or passes one per call; the standalone release ships none, so
# this stays None there and every channel turn is dropped.
DEFAULT_TRANSPORT: Any = None


def load_transport(path: Path | str) -> Any:
    """The ``Transport`` class of the module at ``path``. Loaded by path on
    purpose: this file must not name any transport module (a ``*.py`` literal
    is an import edge to both closure checks), so the caller names it."""
    spec = importlib.util.spec_from_file_location("nockbrain_transport", str(path))
    if spec is None or spec.loader is None:
        raise ValueError(f"transport module not loadable: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Transport


def ingest_file(path: Path | str, include_sidechain: bool = False, transport: Any = None) -> dict[str, Any]:
    """Ingest one transcript. ``transport`` is a factory for per-file
    transport state (``Transport`` from ``load_transport``); None uses
    ``DEFAULT_TRANSPORT``."""
    factory = DEFAULT_TRANSPORT if transport is None else transport
    state = factory() if factory is not None else None
    transcript = Path(path)
    stats = new_stats()
    events: list[dict[str, Any]] = []
    denied_tool_use_ids: set[str] = set()
    with transcript.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            stats["lines_read"] += 1
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                stats["malformed_lines"] += 1
                continue
            events.extend(
                line_events(
                    raw,
                    transcript,
                    line_number,
                    stats,
                    include_sidechain,
                    denied_tool_use_ids,
                    transport=state,
                )
            )
    stats["events_written"] = len(events)
    return {"events": events, "stats": stats}


def iter_input_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.glob("*.jsonl")))
        else:
            files.append(path)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest Claude Code JSONL transcripts")
    parser.add_argument("paths", nargs="+", type=Path, help="JSONL transcript file(s) or directories")
    parser.add_argument("--output", type=Path, default=None, help="Write sanitized events as JSONL")
    parser.add_argument("--include-sidechain", action="store_true")
    parser.add_argument("--pretty", action="store_true", help="Print full result JSON to stdout")
    parser.add_argument("--transport", type=Path, default=None,
                        help="transport module for channel-framed turns (a deployment "
                             "passes its own); without it every <channel turn is dropped")
    args = parser.parse_args()
    transport = load_transport(args.transport) if args.transport is not None else None

    all_events: list[dict[str, Any]] = []
    total = new_stats()
    for file_path in iter_input_files(args.paths):
        result = ingest_file(file_path, include_sidechain=args.include_sidechain, transport=transport)
        all_events.extend(result["events"])
        for key, value in result["stats"].items():
            total[key] = total.get(key, 0) + value

    if args.output:
        secure_write_text(
            args.output,
            "".join(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n" for event in all_events),
        )

    total["events_written"] = len(all_events)
    if transport is None and total.get("channel_wrappers_dropped"):
        # Loud, not fatal: a run that forgot its transport would
        # otherwise lose every channel turn with only a counter to show.
        print(f"[ingest-jsonl] {total['channel_wrappers_dropped']} channel-framed "
              "turn(s) dropped: no --transport given (pass the deployment's "
              "transport module)", file=sys.stderr)
    result = {"events": all_events, "stats": total}
    if args.pretty:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps({"stats": total}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
