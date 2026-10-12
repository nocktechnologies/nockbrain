#!/usr/bin/env python3
"""Budget-aware memory recall: retrieve facts within a token budget.

Returns a curated summary of relevant past-session facts that fits
within a configurable token cap.

Usage:
    python3 budget-recall.py "what did we decide about content strategy"
    python3 budget-recall.py --budget 800 "status of the audit"
    python3 budget-recall.py --budget 1500 --include-superseded "pricing history"
    python3 budget-recall.py --strict-verify "..."   # only signed+valid facts
"""
# Deferred annotations keep this script runnable on Python 3.9 (stock macOS
# /usr/bin/python3): the recall hook resolves plain `python3` from PATH, and
# PEP 604 unions in def signatures are a def-time TypeError before 3.10.
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from _facts import RECALL_ITEM_FIELDS, fact_currently_valid, fact_source
from _revoke import REVOCATIONS_FILENAME, load_revocations, resurrected_ids

DEFAULT_FACTS = Path.home() / ".nock-brain" / "facts.json"
DEFAULT_INSIGHTS = Path.home() / ".nock-brain" / "insights.json"
CHARS_PER_TOKEN = 4
DEFAULT_BUDGET = 1000
MAX_BUDGET = 1500
MIN_CONFIDENCE = 0.7
SHARED_SOURCE = "shared"

QUERY_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "been", "but", "by",
    "can", "did", "do", "does", "for", "from", "had", "has", "have",
    "how", "i", "in", "is", "it", "me", "of", "on", "or", "our",
    "please", "remind", "show", "tell", "that", "the", "their", "this",
    "to", "us", "was", "we", "were", "what", "when", "where", "which",
    "who", "why", "with", "you", "your",
}

# --- Per-batch diversity cap -----------------------------------------------
# A post-scoring SELECTION constraint (scoring itself is untouched): cap how
# many facts that share the SAME source_date may sit in the front of a recall
# result. A single bulk import (e.g. a one-day backfill that is most of the
# store) otherwise term-matches almost any generic/recency query and crowds
# the top-K. Recency decay alone does not fix it because durable-kind facts
# barely decay and sheer volume wins. This caps any one import's footprint
# regardless of kind. Env-configurable via NOCKBRAIN_MAX_PER_DATE; 0 (or any
# value <= 0) disables the cap entirely (legacy/unbounded behavior).
DEFAULT_MAX_PER_DATE = 4

# Per-prompt ceiling on curated-memory facts (source "curated-memory"). The
# curated slice is high-confidence and large enough to crowd session facts out
# of recall; the freed slots go to the next-best non-curated facts.
CURATED_SOURCE = "curated-memory"
DEFAULT_MAX_CURATED = 2

# BM25 parameters (Okapi defaults). k1 controls term-frequency saturation; b
# controls how strongly document length is normalized.
BM25_K1 = 1.5
BM25_B = 0.75

# --- Recency decay ---------------------------------------------------------
# A fact's score is multiplied by an exponential half-life decay on its
# source_date so a stale fact no longer outranks a current one purely on term
# match. Half-lives are PER-KIND: a "status" or "dispatch" line goes stale in
# days, while a "decision" or "directive" stays load-bearing for months. Tune
# these by editing the dict; they are the only knob for the decay curve.
#
# half-life H means score is halved every H days of age:
#     recency_factor = 0.5 ** (age_days / H)
# A very large H (DURABLE_HALF_LIFE) is effectively "never decays".
RECENCY_HALF_LIFE_DAYS: dict[str, float] = {
    # Fast-decaying / point-in-time kinds: yesterday's status is noise today.
    "status": 14.0,
    "dispatch": 14.0,
    "feed": 14.0,
    "merge": 30.0,
    "bug": 45.0,
    # Durable kinds: decisions/directives/corrections/identity stay relevant.
    "decision": 180.0,
    "directive": 180.0,
    "correction": 180.0,
    "architecture": 180.0,
    # Synthesized insights inherit a FROZEN source_date (the day they were first
    # distilled, often a historical bulk import), so a 180-day half-life lets
    # stale insights bury recent raw facts in recall. Decay them faster so recent
    # work surfaces (one bulk import was most of the insights and dominated recall).
    "insight": 45.0,
    "identity": 100000.0,  # ~never decays
}
# Used for any kind not in the table above (and as a safe middle ground).
DEFAULT_HALF_LIFE_DAYS = 60.0
# Floor so a very old fact never decays fully to zero (it would be unrankable
# even when it is the only term match). Keeps recency a tie-breaker, not a wall.
MIN_RECENCY_FACTOR = 0.01

# --- Bulk-date down-weight (A3) ---------------------------------------------
# A single bulk import (a backfill that is most of the store) term-matches
# almost any query. Per-kind recency decay does not fix it (durable kinds barely
# decay), and the post-scoring per-date diversity cap only REORDERS the front of
# the result; the bulk date still floods the candidate pool and stays ~45% of
# recall-eligible facts. This applies a mild, SCORE-level penalty to facts whose
# source_date is OVER-REPRESENTED in the *candidate corpus* of a query, so no
# single date can monopolize ranking. Conservative by construction: it triggers
# ONLY above a share threshold and is floored, so a normal date (a few % of the
# corpus) is untouched and a legitimately-relevant old fact is down-weighted,
# never crushed. Env overrides: NOCKBRAIN_BULK_DATE_THRESHOLD (share above which
# a date is penalized; <=0 or >=1 disables) and NOCKBRAIN_BULK_DATE_MIN_FACTOR.
BULK_DATE_SHARE_THRESHOLD = 0.25
BULK_DATE_MIN_FACTOR = 0.5


def _resolve_bulk_date_params() -> tuple[float, float]:
    """Resolve (threshold, floor) for the bulk-date penalty from env, falling
    back to the module defaults. A non-float env value is ignored rather than
    crashing the live recall path."""
    threshold = BULK_DATE_SHARE_THRESHOLD
    floor = BULK_DATE_MIN_FACTOR
    raw = os.environ.get("NOCKBRAIN_BULK_DATE_THRESHOLD", "").strip()
    if raw:
        try:
            threshold = float(raw)
        except ValueError:
            pass
    raw = os.environ.get("NOCKBRAIN_BULK_DATE_MIN_FACTOR", "").strip()
    if raw:
        try:
            floor = float(raw)
        except ValueError:
            pass
    return threshold, floor


def bulk_date_factor(share: float, threshold: float, floor: float) -> float:
    """Mild multiplicative penalty for a fact from an over-represented date.

    `share` is the date's fraction of the candidate corpus. At or below
    `threshold` the factor is 1.0 (untouched). Above it the factor falls
    linearly with the excess share and is clamped at `floor`, so even a date
    that is the overwhelming majority of candidates is down-weighted, not
    erased. A threshold outside (0, 1) disables the penalty entirely."""
    if threshold <= 0 or threshold >= 1 or share <= threshold:
        return 1.0
    excess = share - threshold
    return max(floor, 1.0 - excess)


def estimate_tokens(text: str) -> int:
    return len(text) // CHARS_PER_TOKEN


def _agent_sources(agent_scope: "str | None") -> "set[str] | None":
    """Return the sources visible to one agent, or None for legacy recall."""
    if not agent_scope or not agent_scope.strip():
        return None
    return {agent_scope.strip(), SHARED_SOURCE}


def _scope_facts(facts: list[dict], agent_scope: "str | None") -> list[dict]:
    sources = _agent_sources(agent_scope)
    if sources is None:
        return facts
    return [fact for fact in facts if fact_source(fact) in sources]


def _normalize_token(token: str) -> str:
    if len(token) > 4 and token.endswith("ies"):
        return token[:-3] + "y"
    if len(token) > 4 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def _tokenize(text: str) -> list[str]:
    # Coerce None/empty to "" so a fact whose content is explicitly null never
    # crashes the recall path (.lower() on None); the live injection path runs
    # this over every candidate fact.
    return [
        _normalize_token(term)
        for term in re.findall(r"[a-z0-9]+", (text or "").lower())
    ]


def _ordered_query_terms(query: str) -> list[str]:
    terms: list[str] = []
    for term in _tokenize(query):
        if term in QUERY_STOPWORDS or term in terms:
            continue
        terms.append(term)
    return terms


def _query_terms(query: str) -> set[str]:
    """Return content-bearing query terms for ranking.

    Prompt-time recall receives natural-language questions. Ranking on every
    token lets high-frequency scaffolding words ("what", "is", "the", "who")
    match generic session notes and bury the real subject. Drop those words and
    rank on the remaining signal terms. If a query has no signal terms, return
    an empty set rather than recalling keyword noise.
    """
    return set(_ordered_query_terms(query))


def _query_pairs(ordered_terms: list[str]) -> list[tuple[str, str]]:
    return list(zip(ordered_terms, ordered_terms[1:]))


def _default_recall_min_matches(query_terms: set[str]) -> int:
    return 2 if len(query_terms) >= 3 else 1


def _pair_window_count(
    doc: list[str],
    pairs: list[tuple[str, str]],
    max_gap: int = 40,
) -> int:
    if not pairs:
        return 0
    positions: dict[str, list[int]] = {}
    for idx, term in enumerate(doc):
        positions.setdefault(term, []).append(idx)

    count = 0
    for left, right in pairs:
        left_positions = positions.get(left, [])
        right_positions = positions.get(right, [])
        if any(
            abs(rpos - lpos) <= max_gap
            for lpos in left_positions
            for rpos in right_positions
        ):
            count += 1
    return count


def _token_spans(text: str) -> list[tuple[str, int, int]]:
    return [
        (_normalize_token(match.group(0).lower()), match.start(), match.end())
        for match in re.finditer(r"[a-z0-9]+", text or "", re.IGNORECASE)
    ]


def _relevant_excerpt(content: str, query_terms: set[str] | None, max_chars: int = 220) -> str:
    content = str(content or "")
    if len(content) <= max_chars or not query_terms:
        return content[:max_chars]

    spans = _token_spans(content)
    hits = [(term, start, end) for term, start, end in spans if term in query_terms]
    if not hits:
        return content[:max_chars]

    best: tuple[int, int, int] | None = None
    for _, start, _ in hits:
        window_start = max(0, start - 30)
        window_end = min(len(content), window_start + max_chars)
        terms_in_window = {
            term for term, span_start, _ in spans
            if window_start <= span_start < window_end and term in query_terms
        }
        score = len(terms_in_window)
        candidate = (score, -window_start, window_start)
        if best is None or candidate > best:
            best = candidate

    start = best[2] if best else hits[0][1]
    end = min(len(content), start + max_chars)
    excerpt = content[start:end].strip()
    if start > 0:
        excerpt = "..." + excerpt
    if end < len(content):
        excerpt += "..."
    return excerpt


def _resolve_now(now: datetime | None = None) -> datetime:
    """Resolve the reference 'now' for recency decay. Injectable for
    deterministic tests: explicit arg > NOCK_BRAIN_NOW env (ISO date/datetime)
    > wall clock. Never a bare datetime.now() buried in the scoring path."""
    if now is not None:
        return now
    env = os.environ.get("NOCK_BRAIN_NOW")
    if env:
        parsed = _parse_date(env)
        if parsed is not None:
            return parsed
    return datetime.now(timezone.utc)


def _parse_date(value) -> datetime | None:
    """Parse a source_date into a datetime, or None if absent/unparseable.
    Accepts 'YYYY-MM-DD', full ISO timestamps, and date objects. Returns None
    for the sentinel 'unknown' or anything we cannot read; callers treat None
    as 'no recency signal' (neutral factor), never as a crash."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    text = str(value).strip()
    if not text or text.lower() == "unknown":
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            return datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None


def recency_factor(fact: dict, now: datetime) -> float:
    """Exponential half-life decay on source_date, with a per-kind half-life.
    Returns a neutral 1.0 for facts with no parseable source_date (backward
    compatible: facts predating recency decay and 'unknown' dates are never
    penalized)."""
    parsed = _parse_date(fact.get("source_date"))
    if parsed is None:
        return 1.0
    # Compare in a tz-consistent way: if one side is naive, drop tz from both.
    ref = now
    if parsed.tzinfo is None and ref.tzinfo is not None:
        ref = ref.replace(tzinfo=None)
    elif parsed.tzinfo is not None and ref.tzinfo is None:
        parsed = parsed.replace(tzinfo=None)
    age_days = (ref - parsed).total_seconds() / 86400.0
    if age_days <= 0:
        return 1.0  # future-dated or same-day facts are fully fresh
    half_life = RECENCY_HALF_LIFE_DAYS.get(
        str(fact.get("kind", "")).lower(), DEFAULT_HALF_LIFE_DAYS
    )
    if half_life <= 0:
        return 1.0
    return max(MIN_RECENCY_FACTOR, 0.5 ** (age_days / half_life))


# --- Source-trust down-weight (S7) ------------------------------------------
# A fact written by an agent/tool rather than distilled from a human-reviewed
# transcript is UNPROVEN until a human promotes it. This is the memory-layer
# prompt-injection defense (mnemosyne's EXTERNAL_WRITE, adapted): an externally
# written fact is kept rankable but DISCOUNTED so it cannot outrank trusted
# facts on term match alone, until promotion clears the marker.
#
# Vocabulary (all optional; absent == trusted, so every existing fact and the
# whole distilled store are unaffected):
#   trust: "trusted" | "untrusted" | "external"   (explicit)
#   provenance: "external_write" | "mcp" | "tool" (marks an external writer)
# A fact is untrusted iff trust is untrusted/external OR provenance names an
# external writer AND trust is not explicitly "trusted". Promotion = set
# trust:"trusted" (or drop the markers), a deliberate human/gated step.
UNTRUSTED_RECALL_FACTOR = 0.5
_EXTERNAL_PROVENANCE = {"external_write", "mcp", "tool", "external"}


def _env_factor(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if 0.0 < value <= 1.0 else default


def is_untrusted(fact: dict) -> bool:
    """True iff the fact is externally/tool-written and not human-promoted."""
    trust = str(fact.get("trust", "")).lower()
    if trust == "trusted":
        return False
    if trust in {"untrusted", "external"}:
        return True
    return str(fact.get("provenance", "")).lower() in _EXTERNAL_PROVENANCE


def trust_factor(fact: dict) -> float:
    """Recall multiplier for source trust: 1.0 for trusted (the default and
    every existing fact), a discount for unproven external writes. Override the
    discount with NOCKBRAIN_UNTRUSTED_FACTOR (0 < x <= 1)."""
    if is_untrusted(fact):
        return _env_factor("NOCKBRAIN_UNTRUSTED_FACTOR", UNTRUSTED_RECALL_FACTOR)
    return 1.0


def supersession_factor(fact: dict) -> float:
    """Soft penalty for facts that are deprecated-but-not-hard-filtered.

    In the current schema, supersession is expressed ONLY via
    `status == "superseded"`, which `search()` removes outright (a hard
    filter) before scoring, so there is no soft-deprecated tier to penalize
    and this returns 1.0 (a documented no-op hook). If a future fact ever
    carries a soft signal (`deprecated: true`, or a `supersedes`/`superseded_by`
    pointer while still status=current), it is down-weighted but kept rankable.
    We deliberately do NOT invent fields the store does not have."""
    if fact.get("deprecated") is True:
        return 0.4
    # A still-current fact that nonetheless announces it is being superseded by
    # something newer: keep it, but let the newer fact win ties.
    if fact.get("status", "current") == "current" and fact.get("superseded_by"):
        return 0.6
    return 1.0


def _exclude_revoked_revisions(facts: list[dict]) -> list[dict]:
    """Drop facts whose ``revision_id`` a current peer lists in
    ``revokes_revision_ids``. Status is unsigned; the v2 DAG is not.
    Empty/missing revision ids are ignored so v1 facts are unaffected."""
    revoked: set[str] = set()
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        if fact.get("status", "current") == "superseded":
            continue
        ids = fact.get("revokes_revision_ids")
        if not isinstance(ids, list):
            continue
        for revision_id in ids:
            if revision_id:
                revoked.add(str(revision_id))
    if not revoked:
        return facts
    return [
        fact for fact in facts
        if str(fact.get("revision_id") or "") not in revoked
    ]


def _exclude_resurrected(facts: list[dict], store_path: "Path | None",
                         key) -> list[dict]:
    """Hide facts a trusted revocation says are dead, even if status=current.

    Same class as verify-facts' resurrection finding. Missing key or
    empty sidecar is a no-op: fail open, matching unsigned verification.
    """
    if not facts or key is None or store_path is None:
        return facts
    events = load_revocations(Path(store_path).parent / REVOCATIONS_FILENAME)
    dead = resurrected_ids(facts, events, key)
    if not dead:
        return facts
    kept = [fact for fact in facts if str(fact.get("id", "")) not in dead]
    dropped = len(facts) - len(kept)
    if dropped:
        print(
            f"recall: excluded {dropped} resurrected fact(s) "
            f"(revocations.jsonl)",
            file=sys.stderr,
        )
    return kept


def search(facts: list[dict], query: str, include_superseded: bool = False,
           now: datetime | None = None,
           sources: "set[str] | list[str] | None" = None,
           min_matched_terms: int | None = None) -> list[dict]:
    """Rank facts against the query with Okapi BM25: proper token matching with
    IDF (rarer query terms count for more) and document-length normalization.
    This replaces a naive substring-overlap count, which both over-matched
    (e.g. "cat" inside "category") and treated every term as equally important.

    The BM25 relevance is then multiplied by confidence, a per-kind recency
    decay (stale status facts no longer beat current ones), and a soft
    supersession penalty. `now` is injectable for deterministic tests.

    `sources` scopes recall to facts owned by those agents (gbrain-style
    per-agent scoping). `None` (the default) means no scoping: exact prior
    behavior, so
    every existing caller is unaffected. A fact's owner is `fact_source(f)`
    (missing source defaults to DEFAULT_SOURCE)."""
    facts = _exclude_revoked_revisions(facts)
    if not include_superseded:
        facts = [f for f in facts if f.get("status", "current") != "superseded"]
        # Bi-temporal gate: a fact outside its validity window (invalid_at passed,
        # or valid_at not yet reached) is not CURRENT, so it drops from default
        # recall, but stays in the store and returns with include_superseded.
        # Facts with no window bounds are always valid (backward compatible).
        _now = _resolve_now(now)
        facts = [f for f in facts if fact_currently_valid(f, _now)]
    if sources is not None:
        # A bare string is a common caller slip: set("alpha") would shatter
        # into {'a','l','p','h'} and silently match nothing. Wrap it.
        allowed = {sources} if isinstance(sources, str) else set(sources)
        facts = [f for f in facts if fact_source(f) in allowed]
    facts = [f for f in facts if f.get("confidence", 0) >= MIN_CONFIDENCE]
    if not facts:
        return []

    ordered_terms = _ordered_query_terms(query)
    query_terms = set(ordered_terms)
    if not query_terms:
        return []
    if min_matched_terms is None:
        min_matched_terms = 1
    query_pairs = _query_pairs(ordered_terms)

    ref_now = _resolve_now(now)

    # Corpus statistics for BM25, computed over the candidate set.
    docs = [_tokenize(f.get("content", "")) for f in facts]
    n_docs = len(docs)
    avgdl = sum(len(d) for d in docs) / n_docs if n_docs else 0.0
    doc_freq: Counter = Counter()
    for d in docs:
        for term in set(d):
            doc_freq[term] += 1

    # Bulk-date down-weight (A3): how much of the candidate corpus each
    # source_date occupies, so an over-represented date (e.g. a bulk import
    # date) gets a mild score penalty and cannot monopolize ranking.
    bulk_threshold, bulk_floor = _resolve_bulk_date_params()
    date_counts: Counter = Counter(str(f.get("source_date", "unknown")) for f in facts)
    date_share = {d: c / n_docs for d, c in date_counts.items()} if n_docs else {}

    results = []
    for f, doc in zip(facts, docs):
        tf = Counter(doc)
        dl = len(doc)
        bm25 = 0.0
        matched_terms = 0
        for term in query_terms:
            df = doc_freq.get(term, 0)
            if df == 0:
                continue
            idf = math.log(1 + (n_docs - df + 0.5) / (df + 0.5))
            freq = tf[term]
            if freq > 0:
                matched_terms += 1
            denom = freq + BM25_K1 * (1 - BM25_B + BM25_B * (dl / avgdl if avgdl else 0))
            if denom > 0:
                bm25 += idf * (freq * (BM25_K1 + 1)) / denom
        if bm25 <= 0:
            continue
        if matched_terms < min_matched_terms:
            continue
        pair_matches = _pair_window_count(doc, query_pairs)
        coverage_boost = 1.0 + (max(0, matched_terms - 1) * 3.0)
        phrase_boost = 1.0 + (pair_matches * 4.0)
        share = date_share.get(str(f.get("source_date", "unknown")), 0.0)
        score = (
            bm25
            * f.get("confidence", 0)
            * recency_factor(f, ref_now)
            * supersession_factor(f)
            * trust_factor(f)
            * coverage_boost
            * phrase_boost
            * bulk_date_factor(share, bulk_threshold, bulk_floor)
        )
        if score > 0:
            results.append((score, pair_matches, matched_terms, f))

    results.sort(key=lambda x: (-x[0], -x[1], -x[2], -x[3].get("confidence", 0)))
    return [f for _, _, _, f in results]


def _resolve_max_per_date(explicit: "int | None" = None) -> int:
    """Resolve the per-source_date diversity cap: explicit arg >
    NOCKBRAIN_MAX_PER_DATE env > DEFAULT_MAX_PER_DATE. A non-integer env value
    is ignored (falls through to the default) rather than crashing the live
    recall path. A value <= 0 means 'unlimited' (cap disabled)."""
    if explicit is not None:
        return explicit
    raw = os.environ.get("NOCKBRAIN_MAX_PER_DATE", "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return DEFAULT_MAX_PER_DATE


def _apply_date_diversity_cap(results: list[dict], max_per_date: int,
                              exempt: "frozenset | set | None" = None) -> list[dict]:
    """Post-scoring selection constraint: NOT a re-score and NOT a filter.

    Cap how many facts sharing the SAME source_date may appear in the front of
    the (already score-sorted) result list. Walk the list in score order, keep a
    fact while its source_date is still under the cap, and DEFER any further
    same-date facts to the tail (still in their relative score order). No fact is
    dropped here; the downstream token-budget truncation then naturally sheds
    the deferred tail first, so a single bulk import can no longer dominate the
    top-K of a generic/recency query while a genuinely top-scored same-date fact
    still survives.

    `exempt` fact ids (the semantic tier's reserved dense slots) bypass the cap
    entirely: an offline evaluation measured the cap demoting the semantically best
    fact because it was the 9th from a bulk-import date. Exempt facts neither
    count toward a date's quota nor get deferred. Default None/empty is the
    exact pre-semantic behavior.

    max_per_date <= 0 disables the cap (returns the list unchanged)."""
    if max_per_date <= 0 or len(results) <= max_per_date:
        return results
    exempt_ids = exempt or frozenset()
    seen: Counter = Counter()
    kept: list[dict] = []
    deferred: list[dict] = []
    for f in results:
        if f.get("id") in exempt_ids:
            kept.append(f)
            continue
        key = str(f.get("source_date", "unknown"))
        if seen[key] < max_per_date:
            seen[key] += 1
            kept.append(f)
        else:
            deferred.append(f)
    return kept + deferred


# --- Attestation verification on the recall hot path (OWASP F5) -------------
# The signed fact envelope (_sign.py) made tampering with facts.json
# *detectable*, but detection only ran in the offline verify-facts.py CLI. The
# recall path that actually injects facts into live sessions never checked it,
# so a poisoned store would be injected undetected. Close that loop here: when
# signing has been set up (a key exists), every loaded fact is verified and
# TAMPERED facts are dropped before ranking, with a one-line stderr count (the
# injection hook discards stderr, so the warning can never leak into a
# session). Unsigned facts stay recallable by default (much of the store
# predates signing) but are counted in the warning; --strict-verify fails
# closed and keeps only VALID facts. No key on disk means verification is
# skipped entirely (pre-signing behavior, and _sign/cryptography are never
# imported, keeping the no-key hot path cost-free).
#
# Cost control: at ~160us per Ed25519 signature, full verification of a
# 2,500-fact store adds ~0.4-0.8s to every recall, most of the hook's <2s
# budget. A sidecar cache (_verify_cache) remembers already-proven signatures
# per store, guarded by the store file's (mtime_ns, size), so a recall over an
# unchanged store skips the signature operations but STILL recomputes and
# compares every fact's committed content hashes, so tampering is detected even
# on a warm cache, and any cache doubt falls back to full verification.


def _resolve_verify_key():
    """Load the attestation-verification key via the shared resolver.

    Returns ``(key, error)``. Missing keys are silent (signing never set up).
    A key file that exists but cannot be loaded returns an error string.
    """
    import _sign
    return _sign.resolve_verify_key()


def _verify_filter(facts: list[dict], verify_key, *, label: str,
                   strict: bool = False, cache=None) -> list[dict]:
    """Enforce attestations on loaded facts (see block comment above).

    TAMPERED facts are always excluded. Default mode keeps UNSIGNED and
    PARENT_SUSPECT facts (backward compatible: their own content is unproven
    or intact respectively, not known-poisoned) and counts them in the stderr
    warning; strict mode keeps only VALID. No key -> facts pass unchanged
    (default fail-open). ``--strict-verify`` with no key is handled by
    select_recall, which refuses to inject.

    `cache` (a _verify_cache handle) is passed to verify_facts so the
    signature operation for already-proven facts is skipped; every status
    is computed identically with or without it, so strict-mode semantics
    are unaffected."""
    if verify_key is None or not facts:
        return facts
    import _sign
    report = _sign.verify_facts(facts, verify_key, verified_cache=cache)
    kept: list[dict] = []
    for fact, item in zip(facts, report["statuses"]):
        status = item["status"]
        if status == _sign.TAMPERED:
            continue
        if strict and status != _sign.VALID:
            continue
        kept.append(fact)
    flagged = [
        (report["tampered"], "tampered", True),
        (report["unsigned"], "unsigned", strict),
        (report["parent_suspect"], "parent-suspect", strict),
    ]
    if any(count for count, _, _ in flagged):
        parts = [
            f"{'excluded' if excluded else 'allowed'} {count} {name}"
            for count, name, excluded in flagged if count
        ]
        print(f"{label}: attestation check: " + "; ".join(parts)
              + f" of {len(facts)} fact(s)"
              + ("" if strict else " (--strict-verify excludes unverified)"),
              file=sys.stderr)
    return kept


def format_fact(f: dict, query_terms: set[str] | None = None) -> str:
    parts = [f"[{f.get('source_date', 'unknown')}]", f"[{f.get('kind', 'fact').upper()}]"]
    header = " ".join(parts)
    content = _relevant_excerpt(str(f.get("content", "")), query_terms, max_chars=320)
    if f.get("status") == "superseded":
        content = f"[SUPERSEDED] {content}"
    return f"{header}\n{content}"


def _load(path: Path, *, verify_key=None, strict_verify: bool = False) -> list[dict]:
    # Backend-agnostic load: JSON stays the default; SQLite engages only
    # when explicitly selected (NOCKBRAIN_STORE=sqlite or the store-v2 marker).
    from _storeback import resolve_store
    store = resolve_store(path)

    def _read():
        return store.load_facts(required_fields=RECALL_ITEM_FIELDS)

    if verify_key is None:
        # Local import of _verify_cache stays off the no-key hot path.
        return _verify_filter(_read(), None, label=str(path),
                              strict=strict_verify, cache=None)

    # for_store owns the cache lifecycle: stamp (before the store is read;
    # for SQLite that stat is brain.db's, not facts.json's), then load,
    # then save on exit. Callers cannot invert the stat-before-read order
    # through this helper.
    import _verify_cache
    with _verify_cache.for_store(store.freshness_path, verify_key, _read) as (
            cache, facts):
        return _verify_filter(facts, verify_key, label=str(path),
                              strict=strict_verify, cache=cache)


_TRUTHY = {"1", "true", "yes", "on"}


def _env_truthy(name: str) -> bool:
    """A flag env var is truthy iff its (case-insensitive, stripped) value is in
    {1,true,yes,on}; absent/anything-else is off. Mirrors the gate the design
    requires for NOCKBRAIN_GRAPH_RECALL."""
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def _maybe_graph_expand(all_facts: list[dict], seeds: list[dict], query: str,
                        include_superseded: bool, now: datetime,
                        graph_expand: bool) -> list[dict]:
    """Gate for graph-augmented recall. When `graph_expand` is False this is a
    PURE pass-through: it returns the exact same `seeds` list object, before any
    graph import/build/allocation runs, so the off-path is byte-identical to
    the flat path. When True, it delegates to _graph_recall.expand(), which
    appends graph neighbors (weighted strictly below the weakest seed) using the
    SAME recency/supersession/confidence gates as search()."""
    if not graph_expand:
        return seeds  # additive guarantee: identical object, zero graph work
    if not seeds:
        return seeds
    import _graph_recall  # local import: never loaded on the off-path
    return _graph_recall.expand(
        all_facts, seeds, include_superseded, now,
        recency_factor=recency_factor,
        supersession_factor=supersession_factor,
        trust_factor=trust_factor,
        min_confidence=MIN_CONFIDENCE,
        currently_valid=fact_currently_valid,
        query_terms=_query_terms(query),
        tokenize=_tokenize,
    )


def budget_recall(query: str, facts_file: Path, budget: int = DEFAULT_BUDGET,
                  include_superseded: bool = False, insights_file: Path | None = None,
                  now: datetime | None = None, graph_expand: bool = False,
                  max_per_date: "int | None" = None,
                  strict_verify: bool = False, semantic: bool = False,
                  agent_scope: "str | None" = None,
                  max_curated: int = DEFAULT_MAX_CURATED) -> str:
    selection = select_recall(
        query, facts_file, budget, include_superseded,
        insights_file=insights_file, now=now, graph_expand=graph_expand,
        max_per_date=max_per_date, strict_verify=strict_verify,
        semantic=semantic, agent_scope=agent_scope, max_curated=max_curated,
    )
    if selection is None:
        return ""
    results = selection["results"]
    output_lines = [f"Memory recall ({len(results)} matches, budget {budget} tokens):"]
    for f in selection["included"]:
        output_lines.append(format_fact(f, selection["query_terms"]))
    remaining = len(results) - len(selection["included"])
    if selection["truncated"] and remaining > 0:
        output_lines.append(f"[...{remaining} more results truncated by budget]")
    output_lines.append(
        f"[{len(selection['included'])} item(s), "
        f"~{selection['tokens_used']} tokens]")
    return "\n\n".join(output_lines)


# --- Per-prompt heuristic-synthesis insight exclusion -----------------------
# The synthesizer stamps every insight's provenance: "heuristic" is the literal
# "Recurring <kind> (N distinct events; M sampled inputs, ...): <theme>. Most
# recent: <excerpt>" template (no synthesizer, or the synthesizer failed/was
# rejected); "llm" is a real judged sentence. The heuristic template is a
# keyword bag, not a fact: any query sharing just 1-2 common words (e.g.
# "plan", "brain") clears search()'s generic min_matched_terms floor, and
# because insight_results is unconditionally placed ahead of fact_results
# below, a handful of these can occupy the whole per-prompt token budget
# before a genuinely on-topic fact is ever considered (observed: the
# same 4-5 rows won on almost every prompt regardless of topic). A
# keyword-bag template has no stable definition of "on-topic" to floor a
# term-overlap ratio against, so per-prompt recall excludes the whole
# provenance instead. Heuristic insights stay in the store, available to any
# other reader (e.g. boot-time context assembly); only per-prompt recall
# here excludes them. LLM-enriched insights and older stores lacking the
# field are unaffected.
HEURISTIC_SYNTHESIS = "heuristic"


def _exclude_heuristic_synthesis(insights: list[dict]) -> list[dict]:
    return [insight for insight in insights
            if insight.get("synthesized_by") != HEURISTIC_SYNTHESIS]


# Default cap on how many synthesized insights may lead a SEMANTIC recall
# result. Measured in an offline evaluation: 20 insights prepended on one query
# consumed most of the 800-token budget before any fused fact. Applies only
# when the semantic tier is on, so the flag-off path stays byte-identical.
# Env-tunable; <= 0 disables the cap.
DEFAULT_INSIGHT_LEAD_CAP = 5


def _resolve_insight_lead_cap() -> int:
    raw = os.environ.get("NOCKBRAIN_INSIGHT_LEAD", "")
    try:
        return int(raw) if raw.strip() else DEFAULT_INSIGHT_LEAD_CAP
    except ValueError:
        return DEFAULT_INSIGHT_LEAD_CAP


# Recall-intent scaffolding to strip from the query before EMBEDDING it (the
# lexical side already drops QUERY_STOPWORDS). These words signal *that*
# recall is wanted, not *what* to recall, and a static mean-pooled embedding
# is diluted by every generic token: measured live, "what did we decide about
# X" ranked X's best fact at dense 28 where bare "X" ranked it 5. Word forms
# are kept raw otherwise; plural-stripping "names"->"name" was measured to
# hurt (different token vector).
EMBED_INTENT_WORDS = {
    "about", "regarding", "decide", "decided", "decision", "decisions",
    "discuss", "discussed", "talked", "mentioned", "asked", "remember",
    "remembered", "recall", "happened",
}


def _embed_query_text(query: str) -> str:
    """Query text for the dense encoder: original word forms, minus lexical
    stopwords and recall-intent scaffolding. Falls back to the raw query when
    filtering would leave nothing."""
    words = re.findall(r"[A-Za-z0-9]+", query)
    kept = [w for w in words
            if w.lower() not in QUERY_STOPWORDS
            and w.lower() not in EMBED_INTENT_WORDS]
    return " ".join(kept) if kept else query


def _maybe_dense_fuse(all_facts: list[dict], seeds: list[dict], query: str,
                      include_superseded: bool, now: datetime,
                      semantic: bool) -> "tuple[list[dict], frozenset]":
    """Gate for dense (semantic) fusion. When `semantic` is False this is a
    PURE pass-through: same list object, no imports, byte-identical off-path
    (the _maybe_graph_expand pattern). When True, _dense_recall.fuse() RRF-
    merges the BM25 seeds with raw-cosine candidates from the vector sidecar
    and nominates reserved dense slots; any unavailability (deps, model,
    sidecar) degrades silently back to the seeds; BM25 is the floor."""
    if not semantic:
        return seeds, frozenset()
    import _dense_recall  # local import: never loaded on the off-path
    try:
        return _dense_recall.fuse(
            all_facts, seeds, query, include_superseded, now,
            min_confidence=MIN_CONFIDENCE,
            currently_valid=fact_currently_valid,
            embed_query=_embed_query_text(query),
        )
    except Exception as exc:  # noqa: BLE001 - BM25 is the floor; a semantic
        # crash must never take down the whole recall.
        print(f"semantic recall failed, using flat BM25: {exc}",
              file=sys.stderr)
        return seeds, frozenset()


def _covered_sources(insight: dict, facts_by_id: dict, verify_key,
                     query_terms: set[str]) -> set[str]:
    """Only a verified, fully rendered, verbatim source replacement can dedup.

    Legacy source_ids name lineage, not coverage. Abstractions and truncated
    excerpts remain useful recall, but never erase the underlying detail.
    """
    if insight.get("kind") != "insight" or verify_key is None:
        return set()
    content = str(insight.get("content", ""))
    if _relevant_excerpt(content, query_terms, max_chars=320) != content:
        return set()
    import _sign
    if _sign.verify_fact(insight, verify_key) != _sign.VALID:
        return set()
    evidence = insight.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != 1:
        return set()
    lineage = evidence[0]
    if not isinstance(lineage, dict) or lineage.get("schema") != "nockbrain-synthesis/v1":
        return set()
    inputs = lineage.get("inputs")
    covered = lineage.get("covered_source_ids")
    if not isinstance(inputs, list) or not isinstance(covered, list):
        return set()
    receipts = {entry.get("id"): entry for entry in inputs
                if isinstance(entry, dict) and isinstance(entry.get("id"), str)}
    normalized = " ".join(content.split())
    result = set()
    for fid in covered:
        if not isinstance(fid, str) or fid not in receipts or fid not in facts_by_id:
            continue
        source = facts_by_id[fid]
        text = " ".join(str(source.get("content", "")).split())
        receipt = receipts[fid]
        if (receipt.get("truncated") is False and text and text in normalized
                and receipt.get("fact_hash") == _sign.canonical_fact_hash(source)):
            result.add(fid)
    return result


def select_recall(query: str, facts_file: "Path | None",
                  budget: int = DEFAULT_BUDGET,
                  include_superseded: bool = False,
                  insights_file: "Path | None" = None,
                  now: "datetime | None" = None, graph_expand: bool = False,
                  max_per_date: "int | None" = None,
                  strict_verify: bool = False,
                  semantic: bool = False,
                  agent_scope: "str | None" = None,
                  max_curated: int = DEFAULT_MAX_CURATED) -> "dict | None":
    """Run the full selection pipeline and return the facts that would be
    injected, as dicts: {results, included, tokens_used, truncated,
    query_terms, reserved_ids}. budget_recall() renders this; the offline
    eval consumes it directly so benchmarks measure production code, not a
    replica. Returns None when nothing matches."""
    ref_now = _resolve_now(now)
    query_terms = _query_terms(query)
    min_matches = _default_recall_min_matches(query_terms)
    verify_key, key_error = _resolve_verify_key()
    if strict_verify and verify_key is None:
        reason = key_error or "no signing key found"
        print(f"budget-recall: --strict-verify fail closed ({reason}); "
              "refusing to inject unverified facts", file=sys.stderr)
        return None
    if key_error:
        print(f"budget-recall: cannot load signing key ({key_error}); "
              "attestation verification skipped", file=sys.stderr)
    reserved_ids: frozenset = frozenset()
    if facts_file:
        all_facts = _exclude_resurrected(
            _scope_facts(
                _load(facts_file, verify_key=verify_key,
                      strict_verify=strict_verify),
                agent_scope,
            ),
            facts_file,
            verify_key,
        )
        fact_results = search(
            all_facts, query, include_superseded,
            now=ref_now, min_matched_terms=min_matches,
        )
        # Dense fusion first, then graph expansion anchors on the fused
        # list: with on-topic dense seeds it enriches rather than drifts.
        fact_results, reserved_ids = _maybe_dense_fuse(
            all_facts, fact_results, query, include_superseded, ref_now,
            semantic,
        )
        fact_results = _maybe_graph_expand(
            all_facts, fact_results, query, include_superseded, ref_now, graph_expand
        )
        if max_curated >= 0:  # negative disables the cap
            n_curated = 0
            capped = []
            for f in fact_results:
                if f.get("source") == CURATED_SOURCE:
                    n_curated += 1
                    if n_curated > max_curated:
                        continue
                capped.append(f)
            fact_results = capped
            kept_ids = {f.get("id") for f in capped}
            reserved_ids = frozenset(i for i in reserved_ids if i in kept_ids)
    else:
        fact_results = []
    if insights_file:
        insight_results = search(
            _exclude_heuristic_synthesis(
                _scope_facts(
                    _load(insights_file, verify_key=verify_key,
                          strict_verify=strict_verify),
                    agent_scope,
                ),
            ),
            query, include_superseded,
            now=ref_now, min_matched_terms=min_matches,
        )
    else:
        insight_results = []
    if semantic:
        lead_cap = _resolve_insight_lead_cap()
        if lead_cap > 0:
            insight_results = insight_results[:lead_cap]

    # Keep source candidates until an actually included, complete insight proves
    # coverage. A skipped/truncated insight must not remove raw BM25 answers.
    covered: set[str] = set()
    facts_by_id = {f.get("id"): f for f in fact_results if f.get("id")}

    # Date diversity applies independently to the two tiers. A summary omitted
    # for budget must never spend a raw fact's date slot and demote that answer.
    date_cap = _resolve_max_per_date(max_per_date)
    results = (_apply_date_diversity_cap(insight_results, date_cap)
               + _apply_date_diversity_cap(fact_results, date_cap, exempt=reserved_ids))
    if not results:
        return None

    header = f"Memory recall ({len(results)} matches, budget {budget} tokens):"
    tokens_used = estimate_tokens(header)
    included: list[dict] = []
    truncated = False

    if not reserved_ids:
        # Preserve raw-fact greedy truncation; omitted insights cannot block sources.
        for f in results:
            if f.get("id") in covered and f.get("kind") != "insight":
                continue
            fact_tokens = estimate_tokens(format_fact(f, query_terms))
            if tokens_used + fact_tokens > budget:
                truncated = True
                if f.get("kind") == "insight":
                    continue  # a shorter source fact may still fit
                break
            included.append(f)
            tokens_used += fact_tokens
            covered.update(_covered_sources(f, facts_by_id, verify_key, query_terms))
    else:
        # Reserved slots are guaranteed: precommit their token cost, then fill
        # the remaining budget greedily. A reserved fact past the truncation
        # point is appended at the tail (it displaced budget, not order).
        committed: list[dict] = []
        reserved_cost = 0
        for f in results:
            if f.get("id") not in reserved_ids:
                continue
            cost = estimate_tokens(format_fact(f, query_terms))
            if tokens_used + reserved_cost + cost > budget:
                break  # budget cannot hold every reserved slot; keep what fits
            committed.append(f)
            reserved_cost += cost
        committed_ids = {f.get("id") for f in committed}
        tokens_used += reserved_cost
        emitted: set = set()
        for f in results:
            fid = f.get("id")
            if fid in committed_ids:
                if fid not in emitted:
                    included.append(f)
                    emitted.add(fid)
                continue
            if fid in covered and f.get("kind") != "insight":
                continue
            fact_tokens = estimate_tokens(format_fact(f, query_terms))
            if tokens_used + fact_tokens > budget:
                truncated = True
                if f.get("kind") == "insight":
                    continue
                break
            included.append(f)
            tokens_used += fact_tokens
            covered.update(_covered_sources(f, facts_by_id, verify_key, query_terms))
        if truncated:
            for f in committed:
                if f.get("id") not in emitted:
                    included.append(f)
                    emitted.add(f.get("id"))

    return {
        "results": results,
        "included": included,
        "tokens_used": tokens_used,
        "truncated": truncated,
        "query_terms": query_terms,
        "reserved_ids": reserved_ids,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("query", nargs="+")
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    parser.add_argument("--facts", type=Path, default=DEFAULT_FACTS)
    parser.add_argument("--insights", type=Path, default=DEFAULT_INSIGHTS,
                        help="Synthesized-insight store (surfaced first); optional")
    parser.add_argument("--include-superseded", action="store_true")
    parser.add_argument("--graph", action="store_true",
                        help="Enable graph-augmented recall (default off; also "
                             "via NOCKBRAIN_GRAPH_RECALL=1)")
    parser.add_argument("--semantic", action="store_true",
                        help="Enable hybrid semantic recall over the vector "
                             "sidecar (default off; also via "
                             "NOCKBRAIN_SEMANTIC=1; degrades to flat BM25 "
                             "when deps/model/sidecar are missing)")
    parser.add_argument("--max-per-date", type=int, default=None,
                        help="Cap facts sharing one source_date in the result "
                             "(default 4; 0 disables; also via "
                             "NOCKBRAIN_MAX_PER_DATE)")
    parser.add_argument("--max-curated", type=int, default=DEFAULT_MAX_CURATED,
                        help="Cap curated-memory facts per prompt (default 2; "
                             "0 excludes them; negative disables the cap)")
    parser.add_argument("--strict-verify", action="store_true",
                        help="Fail closed: recall only facts whose attestation "
                             "verifies as valid; an unusable key yields empty "
                             "recall (default also excludes tampered facts but "
                             "still allows unsigned ones; also via "
                             "NOCKBRAIN_STRICT_VERIFY=1)")
    parser.add_argument("--agent-scope", default=None,
                        help="Recall this agent's private facts plus shared "
                             "facts (also via NOCKBRAIN_AGENT_SCOPE); omitted "
                             "keeps unscoped legacy behavior")
    args = parser.parse_args()

    budget = min(args.budget, MAX_BUDGET)
    query_str = " ".join(args.query)
    graph_expand = args.graph or _env_truthy("NOCKBRAIN_GRAPH_RECALL")
    strict_verify = args.strict_verify or _env_truthy("NOCKBRAIN_STRICT_VERIFY")
    semantic = args.semantic or _env_truthy("NOCKBRAIN_SEMANTIC")
    agent_scope = args.agent_scope or os.environ.get("NOCKBRAIN_AGENT_SCOPE")
    result = budget_recall(query_str, args.facts, budget, args.include_superseded,
                           insights_file=args.insights, graph_expand=graph_expand,
                           max_per_date=args.max_per_date,
                           strict_verify=strict_verify, semantic=semantic,
                           agent_scope=agent_scope, max_curated=args.max_curated)

    if result:
        print(result)
    else:
        print("No matching facts found.")


if __name__ == "__main__":
    main()
