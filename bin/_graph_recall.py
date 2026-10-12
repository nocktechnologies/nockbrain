"""Graph-augmented recall traversal (Graphify merge into budget-recall).

This module holds the ONLY graph-expansion logic. It is invoked from
budget-recall.py's `_maybe_graph_expand()` and is reached *only* when the
graph flag is on; the off-path never imports or calls anything here.

The graph itself is built by `export-graph.graph_from_facts()` VERBATIM (we do
not reinvent concept extraction). We read its MENTIONS edges (fact -> concept)
and SUPPORTS edges (session -> fact) to find facts that neighbor a flat BM25 hit
without sharing any query term. Those neighbors are weighted strictly BELOW the
weakest flat hit, re-using the SAME confidence / recency / supersession gates as
`search()`, and the seeds are always emitted first in their original order so
expansion is strictly additive. An optional NOCKBRAIN_GRAPH_MIN_SHARED_TERMS
gate (default off) can additionally require neighbors of long queries to touch
at least N query terms.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from datetime import datetime
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))


def _load_export_graph():
    """Load export-graph by path (its filename is hyphenated, so a bare
    `import export-graph` is impossible). Cached on the function object."""
    cached = getattr(_load_export_graph, "_mod", None)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(
        "export_graph", BIN_DIR / "export-graph.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _load_export_graph._mod = mod
    return mod


# Default knobs. GRAPH_WEIGHT is deliberately << 1 so a graph neighbor's score
# lands below any direct BM25 hit; SESSION_WEIGHT is lower still for neighbors
# that share only a session (no concept overlap). GRAPH_MAX_NEIGHBORS caps the
# candidate set so a hub concept can't explode it before budgeting.
DEFAULT_GRAPH_WEIGHT = 0.30
DEFAULT_SESSION_WEIGHT = 0.15
DEFAULT_MAX_NEIGHBORS = 20
# Optional anti-drift gate for long (>=3 signal-term) queries: a neighbor must
# share at least this many query terms or it is dropped. Default 0 = no gate:
# the module exists to surface zero-overlap neighbors. 1 is the meaningful
# guard setting (seeds already require >=2 matched terms, so 1 admits only
# graph-connected facts that at least touch the query's subject). Values >=2
# are vacuous: any fact sharing >=2 terms of a >=3-term query is already a
# BM25 seed, so the gate would filter every possible neighbor. This was the
# hardcoded behavior before 2026-07-10 and made expansion a silent no-op for
# every natural multi-word question.
DEFAULT_MIN_SHARED_TERMS = 0


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def expand(all_facts, seeds, include_superseded, now, *,
           recency_factor, supersession_factor, min_confidence,
           currently_valid=None, query_terms=None, tokenize=None,
           trust_factor=None):
    """Return a re-ranked SUPERSET of `seeds`: the seeds first, in their
    original BM25 order, followed by graph neighbors sorted by descending
    graph_score (always strictly below the weakest seed).

    Callers pass `recency_factor` / `supersession_factor` / `min_confidence`
    from budget-recall so graph facts obey the exact same recency decay and
    confidence gate as the flat path. `now` is the already-resolved reference
    clock so the recency weighting matches the seed scoring clock.
    """
    if not seeds:
        return seeds

    graph_weight = _env_float("NOCKBRAIN_GRAPH_WEIGHT", DEFAULT_GRAPH_WEIGHT)
    session_weight = _env_float("NOCKBRAIN_GRAPH_SESSION", DEFAULT_SESSION_WEIGHT)
    max_neighbors = _env_int("NOCKBRAIN_GRAPH_MAX_NEIGHBORS", DEFAULT_MAX_NEIGHBORS)
    min_shared_terms = _env_int(
        "NOCKBRAIN_GRAPH_MIN_SHARED_TERMS", DEFAULT_MIN_SHARED_TERMS
    )
    session_enabled = session_weight > 0

    eg = _load_export_graph()
    graph = eg.graph_from_facts(all_facts)
    edges = graph.get("edges", [])

    # Adjacency maps from the exported graph.
    concept_to_facts: dict[str, set[str]] = {}
    fact_to_concepts: dict[str, set[str]] = {}
    session_to_facts: dict[str, set[str]] = {}
    fact_to_sessions: dict[str, set[str]] = {}
    for e in edges:
        etype = e.get("type")
        src = e.get("source", "")
        tgt = e.get("target", "")
        if etype == "MENTIONS":  # source=fact, target=concept
            concept_to_facts.setdefault(tgt, set()).add(src)
            fact_to_concepts.setdefault(src, set()).add(tgt)
        elif etype == "SUPPORTS":  # source=session, target=fact
            session_to_facts.setdefault(src, set()).add(tgt)
            fact_to_sessions.setdefault(tgt, set()).add(src)

    # fact_id ('fact:<id>') -> fact dict, from the live fact list (skip id-less
    # facts: the graph keys on 'fact:<id>', so they can't be graph targets).
    fact_by_id: dict[str, dict] = {}
    for f in all_facts:
        fid = f.get("id")
        if fid is None:
            continue
        fact_by_id[f"fact:{fid}"] = f

    seed_ids = {f"fact:{f['id']}" for f in seeds if f.get("id") is not None}
    if not seed_ids:
        return seeds  # nothing to anchor expansion on -> degrade to flat

    # NEIGHBOR GATHER + WEIGHT. A candidate neighbor accumulates:
    #  - per shared concept: graph_weight * concept_idf_bonus  (more bridges win)
    #  - per shared session (concept-less neighbors): session_weight
    # concept_idf_bonus inverts hub size so a concept mentioned by everything
    # down-weights vs a rare bridging concept.
    raw_scores: dict[str, float] = {}
    via_concept: set[str] = set()

    for seed_id in seed_ids:
        for concept in fact_to_concepts.get(seed_id, set()):
            members = concept_to_facts.get(concept, set())
            idf_bonus = 1.0 / max(1, len(members))
            for cand_id in members:
                if cand_id in seed_ids:
                    continue
                raw_scores[cand_id] = raw_scores.get(cand_id, 0.0) + (
                    graph_weight * idf_bonus
                )
                via_concept.add(cand_id)

    if session_enabled:
        for seed_id in seed_ids:
            for session in fact_to_sessions.get(seed_id, set()):
                for cand_id in session_to_facts.get(session, set()):
                    if cand_id in seed_ids:
                        continue
                    raw_scores[cand_id] = raw_scores.get(cand_id, 0.0) + session_weight

    # Build weighted candidates, applying the SAME gates as search().
    candidates: list[tuple[float, dict]] = []
    for cand_id, base in raw_scores.items():
        f = fact_by_id.get(cand_id)
        if f is None:
            continue
        if not include_superseded and f.get("status", "current") == "superseded":
            continue
        # Bi-temporal gate: graph neighbors outside their validity window are not
        # current, so they do not get pulled in via expansion either (same rule
        # as the flat path). No-op when currently_valid is not injected.
        if not include_superseded and currently_valid is not None and not currently_valid(f, now):
            continue
        if f.get("confidence", 0) < min_confidence:
            continue
        if (min_shared_terms > 0 and query_terms and len(query_terms) >= 3
                and tokenize is not None):
            shared = set(tokenize(f.get("content", ""))) & set(query_terms)
            if len(shared) < min_shared_terms:
                continue
        graph_score = (
            base
            * f.get("confidence", 0)
            * recency_factor(f, now)
            * supersession_factor(f)
            * (trust_factor(f) if trust_factor is not None else 1.0)
        )
        if graph_score <= 0:
            continue
        candidates.append((graph_score, f))

    if not candidates:
        return seeds

    candidates.sort(key=lambda x: (-x[0], -x[1].get("confidence", 0)))
    neighbor_facts = [f for _, f in candidates[:max_neighbors]]

    # Seeds first (original order, never reordered), then neighbors by score.
    # Concatenation already guarantees "direct hits first".
    return list(seeds) + neighbor_facts
