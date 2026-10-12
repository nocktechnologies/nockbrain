"""Hybrid semantic recall: RRF fusion of BM25 seeds with dense candidates.

Invoked ONLY from budget-recall's `_maybe_dense_fuse()` when the semantic
flag is on; the off-path never imports this module.

Design points, each measured in an offline evaluation:

- Dense candidates rank by RAW cosine with FILTER-only gates (superseded /
  validity / min-confidence). Multiplying cosine by recency demolished a
  perfect paraphrase match: cosine lives in a ~0.2-0.6 band, so a 0.44
  recency factor buries it under recent noise. Recency stays a lexical-side
  and selection-time concern.
- Reciprocal Rank Fusion (k=60) merges the two lists without score
  calibration. Seeds that also appear dense collect both terms.
- RRF alone under-serves strong dense-only hits on noisy stores (a dense
  rank-3 hit fused to 24), so the top RESERVED_SLOTS dense-only facts are
  nominated as reserved: budget-recall guarantees them injection and exempts
  them from the date diversity cap.
- Vectors whose stored content hash no longer matches the live fact are
  stale and skipped: the sidecar is derived data, never authoritative.

Any unavailability (numpy/tokenizers missing, no model assets, no or
mismatched sidecar) degrades silently to the BM25 seeds; a one-line note
goes to stderr, which the injection hook keeps out of sessions.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

DEFAULT_RRF_K = 60
DEFAULT_DENSE_TOP = 40
# 3, per a two-store sweep (k in {0,1,2,3,5,7} on a 2.5k-fact store and a
# 1.8k-fact store): k=3 attains the maximum hit rate on both (8/8 and 7/9),
# k<3 loses the larger store's flagship zero-overlap paraphrase (its
# dense-only rank is 3), and k>3 buys nothing while precommitting ~2 more
# facts of token budget that displaces the lexical tail. The one observed
# semantic regression (the smaller store) is caused by RRF
# composition itself (it persists at k=0 and at every NOCKBRAIN_RRF_K
# tested), so bigger/smaller reservations cannot fix it.
DEFAULT_RESERVED_SLOTS = 3


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def fuse(all_facts: list, seeds: list, query: str, include_superseded: bool,
         now: datetime, *, min_confidence: float,
         currently_valid=None, sidecar_path: "Path | None" = None,
         embed_query: "str | None" = None):
    """Return (fused_results, reserved_ids). Falls back to (seeds, empty) on
    any semantic-tier unavailability; BM25 is always the floor."""
    import _embed

    rrf_k = _env_int("NOCKBRAIN_RRF_K", DEFAULT_RRF_K)
    dense_top = _env_int("NOCKBRAIN_DENSE_TOP", DEFAULT_DENSE_TOP)
    reserved_slots = _env_int("NOCKBRAIN_RESERVED_SLOTS",
                              DEFAULT_RESERVED_SLOTS)

    try:
        encoder = _embed.get_encoder()
        sidecar = _embed.load_sidecar(
            sidecar_path or _embed.DEFAULT_SIDECAR,
            expect_model=encoder.model_id,
        )
    except _embed.EmbedUnavailable as exc:
        print(f"semantic recall unavailable, using flat BM25: {exc}",
              file=sys.stderr)
        return seeds, frozenset()
    if sidecar is None:
        print("semantic recall: no usable vector sidecar "
              "(run bin/embed-facts.py); using flat BM25", file=sys.stderr)
        return seeds, frozenset()

    import numpy as np

    query_vec = encoder.encode([_embed.embed_text(embed_query or query)])[0]
    # np.errstate: numpy 2.0 on macOS Accelerate emits spurious divide/
    # overflow/invalid warnings from this matmul (fixed upstream by 2.4);
    # results were verified element-exact against a float64 einsum (max diff
    # 6e-8), and the warnings would otherwise append to the hook error log on
    # every prompt.
    with np.errstate(all="ignore"):
        sims = sidecar["mat"] @ query_vec
    # Cosine of valid normalized vectors is always finite, so a non-finite
    # sim marks a corrupt sidecar row (e.g. inf minted by load_sidecar's
    # float32 cast) that errstate above would otherwise hide. A +inf sim
    # would rank FIRST and hijack a reserved slot on every prompt, so sort
    # corrupt rows past every finite one and stop before reaching them.
    finite = np.isfinite(sims)
    if not finite.all():
        print(f"semantic recall: skipped {int((~finite).sum())} non-finite "
              "similarity row(s) (corrupt sidecar? re-run bin/embed-facts.py)",
              file=sys.stderr)
    order = np.argsort(np.where(finite, -sims, np.inf))

    by_id = {}
    for f in all_facts:
        fid = f.get("id")
        if fid is not None and fid not in by_id:
            by_id[fid] = f

    dense: list = []
    for idx in order:
        if not finite[idx]:
            break  # corrupt rows all sort last; nothing usable beyond
        fact_id = sidecar["ids"][idx]
        fact = by_id.get(fact_id)
        if fact is None:
            continue  # orphan vector: fact purged/pruned since embedding
        if sidecar["hashes"][idx] != _embed.content_hash(fact.get("content")):
            continue  # stale vector: fact content changed since embedding
        if not include_superseded and fact.get("status", "current") == "superseded":
            continue
        if (not include_superseded and currently_valid is not None
                and not currently_valid(fact, now)):
            continue
        if fact.get("confidence", 0) < min_confidence:
            continue
        dense.append(fact)
        if len(dense) >= dense_top:
            break

    if not dense:
        return seeds, frozenset()

    # Reciprocal Rank Fusion over the two ranked lists.
    scores: dict = {}
    first_seen: dict = {}
    for ranked in (seeds, dense):
        for rank, fact in enumerate(ranked, 1):
            fid = fact.get("id")
            scores[fid] = scores.get(fid, 0.0) + 1.0 / (rrf_k + rank)
            first_seen.setdefault(fid, fact)
    fused = [first_seen[fid]
             for fid in sorted(scores, key=lambda i: -scores[i])]

    seed_ids = {f.get("id") for f in seeds}
    reserved = frozenset(
        f.get("id") for f in dense[:reserved_slots]
        if f.get("id") not in seed_ids
    )
    return fused, reserved
