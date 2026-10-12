"""Optional semantic-embedding tier: raw static encoder + vector sidecar.

The encoder is potion-base-8M loaded RAW: a static model is just a
token-embedding matrix, so runtime encoding is tokenizer lookup + mean-pool +
L2-normalize (verified cosine-1.0 parity against the model2vec library, which
stays install-time-only). Runtime deps are numpy + tokenizers, and this module
is imported lazily by callers so the stdlib-only core never pays for it.

The sidecar (`~/.nock-brain/embeddings.npz`) is DERIVED data, never
authoritative: rows are keyed by fact id + content hash, recall must join back
to the fact store, and purge-fact deletes rows with their facts (a purged fact
may not leave a vector behind, since embeddings are content-derived).

NOCKBRAIN_EMBED_STUB=1 swaps in a deterministic hash-based encoder so tests
and CI never download model files.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path
from typing import Any

# bin/ has no package structure; import sibling helpers by adding bin/ to path.
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

# Facts are embedded on at most this prefix, which matches the store's own content
# cap (p99 measured at 1,500 chars) so hashes stay stable if a longer content
# ever appears.
EMBED_MAX_CHARS = 1500

DEFAULT_SIDECAR = Path.home() / ".nock-brain" / "embeddings.npz"
DEFAULT_MODEL_DIR = Path.home() / ".nock-brain" / "model"

# Tokens excluded from mean-pooling. Including [CLS]/[SEP] was measured to
# drop parity with the reference implementation to cosine 0.96.
SPECIAL_TOKENS = {"[CLS]", "[SEP]", "[PAD]", "[MASK]"}


class EmbedUnavailable(RuntimeError):
    """Semantic tier cannot run here (missing deps or model assets).

    Callers on the recall path must catch this and degrade to BM25 silently;
    CLI tools should surface the message."""


def _deps_hint() -> str:
    """Remediation hint for a missing numpy/tokenizers import. When the
    canonical ~/.nock-brain/venv exists, point there instead of at pip:
    bare `python3` is PATH/alias-dependent (Homebrew builds ship without
    tokenizers), so "pip install" often targets the wrong interpreter."""
    venv_python = Path.home() / ".nock-brain" / "venv" / "bin" / "python3"
    if venv_python.exists():
        return f"rerun with {venv_python}"
    return "pip install numpy tokenizers"


def embed_text(fact_content: Any) -> str:
    return str(fact_content or "")[:EMBED_MAX_CHARS]


def content_hash(fact_content: Any) -> str:
    return hashlib.sha256(embed_text(fact_content).encode("utf-8")).hexdigest()


def _l2norm(mat):
    import numpy as np

    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return (mat / norms).astype(np.float32)


class StubEncoder:
    """Deterministic content-hash encoder for tests/CI. No model assets."""

    model_id = "stub-hash-32"
    dim = 32

    def encode(self, texts: "list[str]"):
        import numpy as np

        rows = []
        for text in texts:
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            raw = np.frombuffer(digest, dtype=np.uint8).astype(np.float32)
            rows.append(raw - raw.mean())
        return _l2norm(np.vstack(rows))


class StaticEncoder:
    """Raw static-embedding encoder: token-matrix lookup,
    skip special tokens, mean-pool, L2-normalize. Symmetric: queries and
    documents encode identically, no prefixes."""

    def __init__(self, model_dir: Path):
        matrix_path = model_dir / "embeddings.npy"
        tokenizer_path = model_dir / "tokenizer.json"
        meta_path = model_dir / "model.json"
        if not matrix_path.exists() or not tokenizer_path.exists():
            raise EmbedUnavailable(
                f"no embedding model at {model_dir} "
                "(run bin/fetch-embed-model.py to install one)"
            )
        try:
            import numpy as np
            from tokenizers import Tokenizer
        except ImportError as exc:  # pragma: no cover - environment-specific
            raise EmbedUnavailable(
                "semantic tier needs numpy + tokenizers "
                f"({_deps_hint()}): {exc}"
            ) from exc
        self._np = np
        self._matrix = np.load(matrix_path, mmap_mode="r")
        self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        meta: "dict[str, Any]" = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                meta = {}
        self.model_id = str(meta.get("model_id") or model_dir.name)
        self.dim = int(self._matrix.shape[1])

    def encode(self, texts: "list[str]"):
        np = self._np
        rows = []
        for encoding in self._tokenizer.encode_batch(list(texts)):
            ids = [
                token_id
                for token_id, token in zip(encoding.ids, encoding.tokens)
                if token not in SPECIAL_TOKENS
            ]
            if ids:
                rows.append(np.asarray(self._matrix[ids]).mean(axis=0))
            else:
                rows.append(np.zeros(self.dim, dtype=np.float32))
        return _l2norm(np.vstack(rows))


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def resolve_model_dir(model_dir: "Path | None" = None) -> Path:
    if model_dir is not None:
        return model_dir
    override = os.environ.get("NOCKBRAIN_EMBED_MODEL_DIR", "").strip()
    return Path(override) if override else DEFAULT_MODEL_DIR


def get_encoder(model_dir: "Path | None" = None):
    if _env_truthy("NOCKBRAIN_EMBED_STUB"):
        return StubEncoder()
    return StaticEncoder(resolve_model_dir(model_dir))


def load_sidecar(path: Path, expect_model: "str | None" = None):
    """Load the vector sidecar as {ids, hashes, model, mat} or None when it is
    absent, unreadable, or built by a different model (a model swap simply
    invalidates everything; re-embedding the whole store takes seconds)."""
    if not path.exists():
        return None
    try:
        import numpy as np
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise EmbedUnavailable(
            f"reading {path} needs numpy ({_deps_hint()}): {exc}") from exc
    try:
        with np.load(path, allow_pickle=False) as archive:
            model_arr = archive["model"]
            if len(model_arr) < 1:
                return None
            sidecar = {
                "ids": [str(i) for i in archive["ids"]],
                "hashes": [str(h) for h in archive["hashes"]],
                "model": str(model_arr[0]),
                "mat": archive["mat"].astype(np.float32),
            }
    except (OSError, KeyError, IndexError, TypeError, ValueError, zipfile.BadZipFile):
        return None
    try:
        n_ids = len(sidecar["ids"])
        if sidecar["mat"].shape[0] != n_ids:
            return None
        if len(sidecar["hashes"]) != n_ids:
            return None
    except (TypeError, AttributeError, IndexError):
        return None
    if not sidecar["model"]:
        return None
    if expect_model is not None and sidecar["model"] != expect_model:
        return None
    return sidecar


def save_sidecar(path: Path, ids: "list[str]", hashes: "list[str]",
                 model: str, mat) -> None:
    """Atomic, owner-only write via _store.secure_replace_bytes."""
    import io

    import numpy as np

    from _store import secure_replace_bytes

    buf = io.BytesIO()
    np.savez(
        buf,
        ids=np.array(ids),
        hashes=np.array(hashes),
        model=np.array([model]),
        mat=np.asarray(mat, dtype=np.float32),
    )
    secure_replace_bytes(path, buf.getvalue())


def sync_sidecar(facts: "list[dict]", encoder, sidecar_path: Path,
                 full: bool = False, batch_size: int = 256) -> "dict[str, int]":
    """Bring the sidecar in line with the fact store: embed new facts, re-embed
    facts whose content hash changed, prune vectors whose fact is gone. `full`
    ignores the existing sidecar and re-embeds everything."""
    import numpy as np

    want: "dict[str, str]" = {}
    texts: "dict[str, str]" = {}
    for fact in facts:
        fact_id = str(fact.get("id") or "")
        if not fact_id or fact_id in want:
            continue
        text = embed_text(fact.get("content"))
        want[fact_id] = content_hash(fact.get("content"))
        texts[fact_id] = text

    existing = None if full else load_sidecar(sidecar_path,
                                              expect_model=encoder.model_id)
    kept_ids: "list[str]" = []
    kept_hashes: "list[str]" = []
    kept_rows: "list" = []
    pruned = 0
    if existing is not None:
        for row, (fact_id, digest) in enumerate(
                zip(existing["ids"], existing["hashes"])):
            if want.get(fact_id) == digest:
                kept_ids.append(fact_id)
                kept_hashes.append(digest)
                kept_rows.append(existing["mat"][row])
            else:
                pruned += 1

    todo = [fact_id for fact_id in want if fact_id not in set(kept_ids)]
    new_rows: "list" = []
    for start in range(0, len(todo), batch_size):
        chunk = todo[start:start + batch_size]
        new_rows.append(encoder.encode([texts[fact_id] for fact_id in chunk]))

    all_ids = kept_ids + todo
    all_hashes = kept_hashes + [want[fact_id] for fact_id in todo]
    parts = []
    if kept_rows:
        parts.append(np.vstack(kept_rows))
    parts.extend(new_rows)
    mat = (np.vstack(parts) if parts
           else np.zeros((0, encoder.dim), dtype=np.float32))
    save_sidecar(sidecar_path, all_ids, all_hashes, encoder.model_id, mat)
    return {"total": len(all_ids), "embedded": len(todo),
            "kept": len(kept_ids), "pruned": pruned}
