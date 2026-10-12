"""Bullet classification shared by the transcript extractors and the standalone importer.

Holds the rules that turn one line of text into a (kind, confidence) pair and
the authority gate, and nothing deployment-specific. Who counts as "the user"
by name, which operational noise to skip, and which machine mints facts are
all caller concerns: the full-install extractors pass their roster and skip
list; the standalone importer passes an empty roster
so a user's "Alice decided" and the operator's own name read identically.
Keeping this module free of deployment data is what lets the standalone release
ship it unchanged.
"""
# Deferred annotations keep this importable on Python 3.9 (stock macOS
# /usr/bin/python3, which non-interactive shells resolve): PEP 604 unions
# in signatures are a def-time TypeError before 3.10.
from __future__ import annotations

import functools
import re
from typing import Iterable

TAGGED_PATTERNS = [
    (r"\[DECISION\]", "decision", 0.9),
    (r"\[DIRECTIVE\]", "directive", 0.9),
    (r"\[CORRECTION\]", "correction", 0.9),
    (r"\[MERGE\]", "merge", 0.9),
    (r"\[DISPATCH\]", "dispatch", 0.9),
    (r"\[ARCHITECTURE\]", "architecture", 0.9),
    (r"\[BUG\]", "bug", 0.9),
    (r"\[CONFIG\]", "config", 0.9),
    (r"\[CONTENT\]", "content", 0.9),
    (r"\[STATUS\]", "status", 0.5),
]

AUTHORITY_KINDS = {"decision", "directive", "correction"}

# Activity events, not durable knowledge: merges, status ticks and dispatches
# are a transaction log wearing a fact-base costume, with no recall value.
# Dropped at classification so neither the markdown nor the JSONL path can
# mint them; a bullet explicitly tagged [MERGE] is still recognized first and
# then dropped, never reclassified by fall-through into another kind.
EVENT_KINDS = {"merge", "status", "dispatch"}

# Role words that name the human principal in any deployment. Personal names
# are added per caller (`names`), never here.
GENERIC_AUTHORITY_WORDS = ("user", "founder", "owner")

NO_NAMES: frozenset = frozenset()


def _roster(names: Iterable[str]) -> frozenset:
    return frozenset(name.casefold() for name in names if name)


def _who(names: frozenset) -> str:
    return "|".join(re.escape(word) for word in GENERIC_AUTHORITY_WORDS + tuple(sorted(names)))


@functools.lru_cache(maxsize=16)
def authority_re(names: frozenset = NO_NAMES) -> "re.Pattern":
    """Text-only authority check used when no actor is known."""
    return re.compile(r"\b(?:%s)\b" % _who(names), re.IGNORECASE)


@functools.lru_cache(maxsize=16)
def inferred_patterns(names: frozenset = NO_NAMES) -> "tuple[tuple[str, str, float], ...]":
    who = _who(names)
    return (
        (r"(?:%s)\b.{0,30}\b(?:decided|approved|locked|chose|picked|selected|wants?)\b" % who, "decision", 0.8),
        (r"(?:%s)\b.{0,30}\b(?:directed|told|asked|said|instructed|requested)\b.{5,}" % who, "directive", 0.75),
        (r"(?:%s)\b.{0,30}\b(?:corrected|caught|pushed back|wrong|mistake)\b" % who, "correction", 0.85),
        (r"\b(?:merged|admin[- ]merge)\b.{0,20}\bPR\s*#\d+", "merge", 0.85),
        (r"\bPR\s*#\d+\b.{0,20}\b(?:merged|admin[- ]merge)\b", "merge", 0.85),
        (r"\b(?:dispatched|activated|assigned)\b.{0,30}\b(?:agent|worker|builder|reviewer)\b", "dispatch", 0.8),
        (r"\b(?:schema|migration|refactor|redesign|architecture)\b.{0,30}\b(?:changed|updated|added|removed|split|merged)\b", "architecture", 0.7),
        (r"\b(?:bug|regression)\b.{0,30}\b(?:found|fixed|caused|root cause)\b", "bug", 0.75),
        (r"\bfixed?\b.{0,20}\b(?:bug|crash|failure|error|leak|bypass)\b", "bug", 0.7),
    )


def classify_bullet(text: str, names: Iterable[str] = NO_NAMES,
                    skip_patterns: Iterable[str] = ()) -> tuple[str, float] | None:
    for skip in skip_patterns:
        if re.search(skip, text, re.IGNORECASE):
            return None
    for pattern, kind, conf in TAGGED_PATTERNS:
        if re.search(pattern, text):
            return None if kind in EVENT_KINDS else (kind, conf)
    for pattern, kind, conf in inferred_patterns(_roster(names)):
        if re.search(pattern, text, re.IGNORECASE):
            return None if kind in EVENT_KINDS else (kind, conf)
    return None


def authority_fact_allowed(kind: str, text: str, actor: str | None = None,
                           names: Iterable[str] = NO_NAMES) -> bool:
    """Only the human principal mints decision/directive/correction facts.

    With a known `actor` (JSONL lanes) the text is not consulted at all: exact
    ``user`` passes, everything else (assistant, tool, channel-bound senders)
    fails. Without one (markdown bullets) the text must name the principal."""
    if kind not in AUTHORITY_KINDS:
        return True
    if actor is not None:
        return actor == "user"
    return bool(authority_re(_roster(names)).search(text))
