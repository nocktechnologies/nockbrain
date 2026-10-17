# Architecture

NockBrain has a command-line entry point, optional Claude Code hooks, a signed
local store, a read-only browser view, and a read-only MCP server. The detailed
user flow is in `docs/how-it-works.md`.

## Capture and review

`bin/consumer-brain.py` dispatches CLI commands. The importer reads only files
named by the user and handles Markdown notes or selected Claude Code JSONL
transcripts. The scrubber removes common secret patterns, and the importer
creates a pending proposal. The CLI shows the full proposal for review; only
`apply` of the reviewed digest can write accepted facts.

The optional Claude Code `Stop` hook follows the same path using the transcript
for that session. It can create a pending proposal but never accepts it. The
`UserPromptSubmit` hook checks whether a prompt asks about earlier work and may
return matching facts. Hook adapters use bounded child processes and add no
recall context when verification fails or a time limit expires.

## Store integrity

The JSON store records facts, proposals, a manifest, signing keys, and signed
revocations. Facts are signed once and remain immutable. Corrections add a new
fact and retain the prior fact as history; forgetting removes the chosen fact
and appends a signed revocation. Journaled writes let `recover` finish an
interrupted accepted change.

`cryptography` enables Ed25519. Without it, the standard library provides an
HMAC-SHA256 fallback. The HMAC public-key file contains the same secret as the
private-key file. Store verification fails closed on tampering or a broken
revocation chain.

## Recall and clients

The consumer hook and MCP `recall` tool use the same verified lexical BM25 path
and 800-token budget. The hook first classifies prompt intent; MCP recall does
not need that check because the client called the tool explicitly. Semantic
search and graph expansion are not enabled in these consumer interfaces.

The MCP server communicates over local stdio and exposes only `recall` and
`status`. Memory Explorer reads a verified snapshot and serves its page on
127.0.0.1 with a per-launch capability token. Neither feature adds a remote
service or a write path.

## Code map

- `bin/_consumer_import.py` parses selected input and scrubs candidates.
- `bin/_consumer_store.py` implements proposal, apply, correction, forgetting,
  validation, locking, and recovery.
- `bin/_sign.py` and `bin/_revoke.py` implement signatures and revocations.
- `bin/budget-recall.py` ranks facts and enforces recall limits.
- `bin/nockbrain-mcp.py` adapts recall and status to MCP over stdio.
- `web/explorer/` contains the read-only browser UI.
