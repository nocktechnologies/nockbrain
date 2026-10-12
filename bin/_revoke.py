"""Signed revocation events (S1): supersession itself becomes attested.

Fact attestations deliberately sign only the immutable core, so lifecycle
marks (status, superseded_by) stay cheap to write, but that leaves one gap:
nothing stops an editor from flipping a superseded fact's status back to
current without breaking any signature. This module closes it. Every
supersession appends a signed, append-only event whose signature covers
exactly the fields that authorize the revocation:

    {superseded_id, superseding_id, reason, superseded_at}

Verification then has teeth in both directions: a superseded fact without a
valid event is *unattested* (legacy, warn), and a CURRENT fact that a valid
event says is dead is *resurrected*: the attack, and a hard failure.

Events live in ``revocations.jsonl`` next to the facts store (0600,
append-only). Signed under the same store key and algorithm family as fact
attestations, with its own domain separator so a revocation signature can
never be confused with a fact signature.

Chained log (2026-10-11): a signed event proves *itself*, but a missing or
garbled line proved nothing: the loader skipped it and nothing recorded how
many events there should be, so resurrecting a fact and garbling its event
line audited clean. Every event minted through ``append_signed_revocation``
now carries, inside the signed payload, a monotonically increasing ``seq``
(1-based over chained events) and ``prev_digest`` = sha256 of the previous
line's exact bytes (``GENESIS_DIGEST`` for the first line of the file). The
audit reports unparseable lines, seq gaps and prev_digest mismatches as
blocking findings. Legacy events (no ``seq``) stay valid; the first chained
event after a legacy tail anchors to that tail's last line; once the chain
has started, a later legacy line is itself a finding (every production writer
chains, so it can only be a bypass or the trace of a deleted chained tail).
The legacy prefix has no digests of its own, so every chained event minted
since 2026-10-11 also signs ``legacy_before`` = the number of legacy
lines ahead of it; deleting or inserting a legacy line then breaks every
later anchored event (``legacy_count_mismatches``). Reordering legacy lines
stays undetectable and is harmless (they are an unordered set of superseded
ids). The writer refuses to append to a log with ANY chain finding, so a
gap is never papered over by reusing an old seq; repair from a backup
first. Ceilings, precisely: (1) no head anchor, so truncation (cutting any
number of trailing lines at a line boundary) is not detectable from the
log alone; (2) before the first anchored event, a legacy line can be deleted
undetectably unless it is the last legacy line (the first chained event's
prev_digest covers that one).
"""
# Deferred annotations keep this importable on Python 3.9 (stock macOS
# /usr/bin/python3, which non-interactive shells resolve): PEP 604 unions
# in signatures are a def-time TypeError before 3.10.
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from _sign import (  # noqa: E402
    SigningKey,
    resolve_signing_key,
)
from _store import FILE_MODE  # noqa: E402

SCHEMA = "nockbrain-revocation/v1"
REVOCATIONS_FILENAME = "revocations.jsonl"
_DOMAIN = b"nockbrain-revocation-v1\n"
# key_id and alg ARE signed: the audit classifies events by them (active vs
# retired key), so leaving them unsigned let an attacker relabel a valid
# event "foreign" to dodge resurrection detection (the F5 threat this
# defends). Signing them makes any relabel break the signature.
_PAYLOAD_FIELDS = (
    "superseded_id", "superseding_id", "reason", "superseded_at", "key_id", "alg",
)
# prev_digest of the first line in a log. A fixed sentinel (not a hash of
# anything) so an empty log has exactly one valid successor.
GENESIS_DIGEST = "0" * 64


def _canonical_payload(event: "dict[str, Any]") -> bytes:
    body: "dict[str, Any]" = {field: str(event.get(field, "")) for field in _PAYLOAD_FIELDS}
    if "seq" in event:
        # Chained event: position and predecessor are signed too, so neither
        # can be rewritten without breaking the signature. Legacy events keep
        # the historical payload so their signatures still verify.
        body["seq"] = event.get("seq")
        body["prev_digest"] = str(event.get("prev_digest", ""))
        if "legacy_before" in event:
            # Count anchor for the legacy prefix: events minted before
            # it have no such field and verify over the historical payload.
            body["legacy_before"] = event.get("legacy_before")
    return _DOMAIN + json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def line_digest(raw_line: bytes) -> str:
    """The chain digest of one log line: sha256 of its exact bytes (the
    line as split on ``\\n``, so the terminating newline is never part of
    it). Exact bytes, not canonical JSON and not CR-tolerant, so any rewrite
    of the append-only file, a trailing ``\\r`` included, is a chain break;
    the writer never emits one."""
    return hashlib.sha256(raw_line).hexdigest()


def sign_revocation(
    key: SigningKey,
    *,
    superseded_id: str,
    superseding_id: str = "",
    reason: str = "",
    superseded_at: "str | None" = None,
    seq: "int | None" = None,
    prev_digest: "str | None" = None,
    legacy_before: "int | None" = None,
) -> "dict[str, Any]":
    """Build and sign one revocation event.

    ``seq``/``prev_digest`` (both or neither) chain the event into the log;
    callers get them from ``chain_position`` under the log's lock;
    ``append_signed_revocation`` does both. Omitting them mints a legacy,
    unchained event (tests, explorer demo). ``legacy_before`` (chained
    events only) signs the number of legacy lines ahead of the event. The
    shared-store writer sets it; the standalone store, whose logs have no legacy
    prefix, does not."""
    if (seq is None) != (prev_digest is None):
        raise ValueError("seq and prev_digest must be given together")
    if legacy_before is not None and (
            seq is None or isinstance(legacy_before, bool)
            or not isinstance(legacy_before, int) or legacy_before < 0):
        raise ValueError("legacy_before must be a non-negative integer on a chained event")
    event: "dict[str, Any]" = {
        "schema": SCHEMA,
        "superseded_id": str(superseded_id),
        "superseding_id": str(superseding_id),
        "reason": str(reason),
        "superseded_at": superseded_at or datetime.now(timezone.utc).isoformat(),
    }
    if seq is not None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise ValueError("seq must be a positive integer")
        event["seq"] = seq
        event["prev_digest"] = str(prev_digest)
        if legacy_before is not None:
            event["legacy_before"] = legacy_before
    # Set before signing so both are covered by the signature (see _PAYLOAD_FIELDS).
    event["alg"] = key.alg
    event["key_id"] = key.key_id
    event["signature"] = key.sign_bytes(_canonical_payload(event))
    event["signed_at"] = datetime.now(timezone.utc).isoformat()
    return event


def verify_revocation(event: Any, key: SigningKey) -> bool:
    """True iff the event's signature verifies over its own payload fields."""
    if not isinstance(event, dict):
        return False
    signature = event.get("signature")
    if not isinstance(signature, str) or not signature:
        return False
    if event.get("alg") != key.alg:
        return False
    return key.verify_bytes(_canonical_payload(event), signature)


class _LockedLog:
    """Exclusive flock over the sidecar for one read-tail-then-append cycle,
    so two writers cannot both mint seq N. Advisory, like edit-fact's store
    lock: every production writer goes through ``append_signed_revocation``
    and holds it only for that cycle, so the (unbounded) wait is at most one
    peer's append. The lock lives on the inode: no production writer
    rename-replaces ``revocations.jsonl`` (the purge tool never touches it,
    backup sync copies out of the store, the standalone store's sidecar is in
    its own directory), so a writer never appends to an orphaned file."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._fd = -1

    def __enter__(self) -> "_LockedLog":
        self._fd = os.open(str(self._path), os.O_RDWR | os.O_CREAT | os.O_APPEND, FILE_MODE)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        except BaseException:
            os.close(self._fd)
            self._fd = -1
            raise
        return self

    def read(self) -> bytes:
        chunks = []
        os.lseek(self._fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(self._fd, 1 << 20)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)

    def append(self, event: "dict[str, Any]") -> None:
        line = (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8")
        view = memoryview(line)
        while view:
            written = os.write(self._fd, view)
            view = view[written:]
        os.fchmod(self._fd, FILE_MODE)

    def __exit__(self, *exc) -> bool:
        if self._fd >= 0:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = -1
        return False


def append_revocation(path: Path, event: "dict[str, Any]") -> None:
    """Append one already-signed event (0600); never rewrites prior lines.

    Raw primitive: assigns no seq. Production writers use
    ``append_signed_revocation`` so the event is chained under the lock."""
    with _LockedLog(path) as log:
        log.append(event)


def parse_revocation_log(data: bytes) -> "tuple[list[dict[str, Any]], dict[str, Any]]":
    """Parse the raw log bytes into (events, chain report).

    ``events`` are the parseable JSON objects in file order, the shape every
    reader always consumed. The chain report is what the old loader threw
    away: ``unparseable_lines``, ``seq_gaps`` and ``prev_digest_mismatches``
    (the seq of each offending chained event), ``unterminated_tail`` (a
    non-empty log whose last byte is not a newline; the writer refuses it),
    ``legacy_after_chain`` (legacy lines that follow a chained event),
    ``legacy_count_mismatches`` (the seq of each chained event whose signed
    ``legacy_before`` disagrees with the legacy lines actually ahead of it),
    ``chained_events``, ``legacy_events``, plus ``next_seq`` and
    ``head_digest`` for the writer.
    """
    events: "list[dict[str, Any]]" = []
    report: "dict[str, Any]" = {
        "unparseable_lines": 0, "seq_gaps": [], "prev_digest_mismatches": [],
        "unterminated_tail": bool(data) and not data.endswith(b"\n"),
        "legacy_after_chain": 0, "legacy_count_mismatches": [],
        "chained_events": 0, "legacy_events": 0,
        "next_seq": 1, "head_digest": GENESIS_DIGEST,
    }
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()  # the terminating newline, not an empty line
    prev_digest = GENESIS_DIGEST
    last_seq = 0
    for raw in lines:
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            event = None
        if not isinstance(event, dict):
            report["unparseable_lines"] += 1
        elif "seq" not in event:
            report["legacy_events"] += 1
            if last_seq:
                report["legacy_after_chain"] += 1
            events.append(event)
        else:
            seq = event.get("seq")
            report["chained_events"] += 1
            if isinstance(seq, bool) or not isinstance(seq, int) or seq != last_seq + 1:
                report["seq_gaps"].append(seq)
            else:
                last_seq = seq
            if event.get("prev_digest") != prev_digest:
                report["prev_digest_mismatches"].append(seq)
            if "legacy_before" in event and event["legacy_before"] != report["legacy_events"]:
                report["legacy_count_mismatches"].append(seq)
            events.append(event)
        prev_digest = line_digest(raw)
    report["next_seq"] = last_seq + 1
    report["head_digest"] = prev_digest
    return events, report


def read_revocation_log(path: Path) -> "tuple[list[dict[str, Any]], dict[str, Any]]":
    """``parse_revocation_log`` over a file; a missing file is an empty log."""
    path = Path(path)
    if not path.exists():
        return parse_revocation_log(b"")
    return parse_revocation_log(path.read_bytes())


def load_revocations(path: Path) -> "list[dict[str, Any]]":
    """Events only, unparseable lines skipped: the recall hot path's reader
    (fail open). Audits use ``read_revocation_log`` so the skipped lines
    count against the log."""
    return read_revocation_log(path)[0]


def chain_position(data: bytes) -> "tuple[int, str]":
    """(next_seq, prev_digest) for the event that would be appended to
    ``data``. For writers that hold their own lock and publish the whole
    file themselves (the standalone store)."""
    report = parse_revocation_log(data)[1]
    return report["next_seq"], report["head_digest"]


def append_signed_revocation(
    path: Path,
    key: SigningKey,
    *,
    superseded_id: str,
    superseding_id: str = "",
    reason: str = "",
    superseded_at: "str | None" = None,
) -> "dict[str, Any]":
    """THE writer: lock the log, read its tail, mint the next chained event,
    append. Returns the event.

    Refuses (``ValueError``, log untouched) when the log has ANY chain
    finding, not only an unterminated tail: after a seq gap the parser's
    ``next_seq`` would reuse an old number and every later event would extend
    a chain the audit already rejects. Repair from a
    backup first; ``record_supersessions`` turns the refusal into a warning."""
    with _LockedLog(path) as log:
        data = log.read()
        if data and not data.endswith(b"\n"):
            raise ValueError(
                f"{path}: revocation log lacks a final newline; refusing to "
                "append (would fuse two events)"
            )
        report = parse_revocation_log(data)[1]
        broken = [field for field in BLOCK_CHAIN if report.get(field)]
        if broken:
            raise ValueError(
                f"{path}: revocation log chain is broken ({', '.join(broken)}); "
                "refusing to append; repair the log from a backup before "
                "minting new events"
            )
        event = sign_revocation(
            key, superseded_id=superseded_id, superseding_id=superseding_id,
            reason=reason, superseded_at=superseded_at,
            seq=report["next_seq"], prev_digest=report["head_digest"],
            legacy_before=report["legacy_events"],
        )
        log.append(event)
    return event


def audit(
    facts: "list[dict[str, Any]]",
    events: "list[dict[str, Any]]",
    key: SigningKey,
    *,
    retired_keys: "tuple[SigningKey, ...]" = (),
    chain: "dict[str, Any] | None" = None,
) -> "dict[str, Any]":
    """Cross-check facts against revocation events, verifying each event
    against a KEYRING (the active key plus any supplied retired keys).

    ``chain`` is the report half of ``read_revocation_log``; when given, its
    ``unparseable_lines`` / ``seq_gaps`` / ``prev_digest_mismatches`` are
    copied into the result so ``blocking_findings`` sees them. Callers that
    only have an event list (recall) get the historical report.

    An event is trusted iff it verifies under some key in the ring, because
    key_id and alg are now signed, a relabeled event verifies under none.
    Classification:

    - ``attested``: verifies under the ACTIVE key.
    - ``foreign_key_events``: verifies under a RETIRED key (a genuine
      pre-rotation revocation): benign, still trusted for resurrection.
    - ``invalid_events``: verifies under NO ring key: tampering, a
      relabel-evasion attempt, or an old event whose key was not supplied.
      Hard-failure class; an unverifiable event is never trusted-benign.
    - ``resurrected``: a fact a TRUSTED event revokes but which is present
      with a non-superseded status: the silent-resurrection attack.
    - ``unattested_superseded``: superseded facts with no trusted event
      (legacy pre-S1 marks); reported, not fatal by default."""
    active_ids: "set[str]" = set()
    trusted_ids: "set[str]" = set()
    attested = 0
    foreign = 0
    invalid = 0
    for event in events:
        if verify_revocation(event, key):
            attested += 1
            active_ids.add(str(event.get("superseded_id", "")))
            trusted_ids.add(str(event.get("superseded_id", "")))
        elif any(verify_revocation(event, retired) for retired in retired_keys):
            foreign += 1
            trusted_ids.add(str(event.get("superseded_id", "")))
        else:
            invalid += 1
    facts_by_id = {
        str(f.get("id", "")): f for f in facts if isinstance(f, dict)
    }
    resurrected = sorted(
        fid for fid in trusted_ids
        if fid in facts_by_id and facts_by_id[fid].get("status") != "superseded"
    )
    unattested = sorted(
        fid for fid, fact in facts_by_id.items()
        if fact.get("status") == "superseded" and fid not in trusted_ids
    )
    report = {
        "attested": attested,
        "invalid_events": invalid,
        "foreign_key_events": foreign,
        "resurrected": resurrected,
        "unattested_superseded": unattested,
    }
    if chain is not None:
        report[BLOCK_UNPARSEABLE] = int(chain.get(BLOCK_UNPARSEABLE, 0))
        report[BLOCK_SEQ_GAP] = list(chain.get(BLOCK_SEQ_GAP, []))
        report[BLOCK_PREV_DIGEST] = list(chain.get(BLOCK_PREV_DIGEST, []))
        report[BLOCK_UNTERMINATED] = bool(chain.get(BLOCK_UNTERMINATED, False))
        report[BLOCK_LEGACY_AFTER_CHAIN] = int(chain.get(BLOCK_LEGACY_AFTER_CHAIN, 0))
        report[BLOCK_LEGACY_COUNT] = list(chain.get(BLOCK_LEGACY_COUNT, []))
        report["chained_events"] = int(chain.get("chained_events", 0))
        report["legacy_events"] = int(chain.get("legacy_events", 0))
    return report


# Blocking-condition constants: the vocabulary every exit path speaks.
BLOCK_INVALID = "invalid_events"
BLOCK_RESURRECTED = "resurrected"
BLOCK_UNATTESTED = "unattested_superseded"
# Log-integrity findings (chained log): always blocking, like invalid events.
BLOCK_UNPARSEABLE = "unparseable_lines"
BLOCK_SEQ_GAP = "seq_gaps"
BLOCK_PREV_DIGEST = "prev_digest_mismatches"
BLOCK_UNTERMINATED = "unterminated_tail"
BLOCK_LEGACY_AFTER_CHAIN = "legacy_after_chain"
BLOCK_LEGACY_COUNT = "legacy_count_mismatches"
BLOCK_CHAIN = (BLOCK_UNPARSEABLE, BLOCK_SEQ_GAP, BLOCK_PREV_DIGEST, BLOCK_UNTERMINATED,
               BLOCK_LEGACY_AFTER_CHAIN, BLOCK_LEGACY_COUNT)


def blocking_findings(report: "dict[str, Any]", *,
                      strict_unattested: bool = False) -> "list[str]":
    """The reasons an audit report must NOT exit success: the single place
    the exit invariant lives.

    Every consumer (verify-facts, backfill, and any future one) routes its
    success/failure decision through this instead of hand-rolling the check at
    each exit, which is how three invalid_events gaps slipped past on three
    exit paths in one PR. Resurrection and invalid (tampered/unverifiable)
    events are ALWAYS blocking. Legacy unattested marks block only under
    ``strict_unattested``; they are a warn-by-default state, not tampering.

    Log-integrity findings (``BLOCK_CHAIN``: an unparseable line, a seq gap,
    a prev_digest mismatch, an unterminated tail, a legacy line after the
    chain started, a legacy-count mismatch) are ALWAYS blocking too: a hole
    in the log is exactly what a garbled revocation looks like.

    Returns an ordered list of blocking reason keys (empty == clean).
    """
    findings: "list[str]" = []
    if report.get(BLOCK_INVALID):
        findings.append(BLOCK_INVALID)
    if report.get(BLOCK_RESURRECTED):
        findings.append(BLOCK_RESURRECTED)
    for field in BLOCK_CHAIN:
        if report.get(field):
            findings.append(field)
    if strict_unattested and report.get(BLOCK_UNATTESTED):
        findings.append(BLOCK_UNATTESTED)
    return findings


def resurrected_ids(
    facts: "list[dict[str, Any]]",
    events: "list[dict[str, Any]]",
    key: "SigningKey | None",
    *,
    retired_keys: "tuple[SigningKey, ...]" = (),
) -> "set[str]":
    """Fact ids a trusted revocation says are dead but status is not superseded.

    Missing key or empty sidecar → empty set (fail open, same as unsigned
    verification). Recall uses this so a status flip-back cannot re-inject
    revoked content that still verifies VALID.
    """
    if key is None or not events:
        return set()
    return set(
        audit(facts, events, key, retired_keys=retired_keys).get("resurrected") or []
    )


def record_supersessions(
    facts_path: Path,
    marked: "list[dict[str, Any]]",
) -> "tuple[int, str | None]":
    """Sign+append one event per freshly-marked fact; never blocks marking.

    Returns (events_written, warning). With no signing key available the
    marks stand but the events are skipped with a loud warning; strict
    verification will then report them as unattested."""
    if not marked:
        return 0, None
    key = resolve_signing_key()
    if key is None:
        return 0, (
            "revocation UNSIGNED (no signing key available); supersession "
            "marks stand but are unattested until backfilled"
        )
    sidecar = Path(facts_path).parent / REVOCATIONS_FILENAME
    written = 0
    for fact in marked:
        try:
            append_signed_revocation(
                sidecar, key,
                superseded_id=str(fact.get("id", "")),
                superseding_id=str(fact.get("superseded_by", "") or ""),
                reason=str(fact.get("supersession_reason", "") or ""),
                superseded_at=str(
                    fact.get("superseded_at", "")
                ) or None,
            )
        except (ValueError, OSError) as exc:
            # Marks stand; the missing events show up as unattested (and the
            # log state itself as a blocking finding) on the next audit.
            return written, (
                f"revocation log refused ({exc}); {len(marked) - written} "
                "supersession mark(s) are unattested until the log is repaired"
            )
        written += 1
    return written, None
