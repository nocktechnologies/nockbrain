"""Explicit hook settings and bounded, public-key recall/capture work for one store."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shlex
import stat
import sys
import tempfile
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from _consumer_import import CUSTOMER_AUTHORITY_NAMES, collect_candidates
from _consumer_store import (ConsumerError, ConsumerStore, FACT_LIMIT,
                             SMALL_LIMIT, _json, _safe_dir, _text, _timestamp,
                             _uuid, canonical_bytes, read_regular)
from _store import secure_replace_bytes

MAX_PROMPT = 2000
MAX_ROOTS = 16
SETTINGS_FILE = "claude-settings.json"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _path_text(value: Path) -> str:
    text = str(value)
    if (not value.is_absolute() or len(text) > 2048 or _CONTROL.search(text) or
            "\\" in text or ".." in value.parts):
        raise ConsumerError("unsafe explicit path")
    try:
        text.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ConsumerError("unsafe explicit path") from exc
    return text


def _root(value: Path, store: Path, *, canonical: bool = False) -> Path:
    root = Path(value)
    _path_text(root)
    if len(root.parts) < 4:
        raise ConsumerError("transcript root is too broad")
    try:
        info = root.lstat()
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ConsumerError("transcript root is unavailable") from exc
    if (not stat.S_ISDIR(info.st_mode) or (canonical and resolved != root) or
            len(resolved.parts) < 4):
        raise ConsumerError("transcript root is unsafe")
    # An alias into a parent of the selected store would allow source files
    # inside the store to be offered as transcripts.
    if store == resolved or store.is_relative_to(resolved):
        raise ConsumerError("transcript root includes the store")
    return root


def setup_hooks(store_path: Path, roots: list[Path]) -> Path:
    """Write only one owner-private, opt-in Claude settings file in this store."""
    store_path = Path(store_path)
    _path_text(store_path)
    if not isinstance(roots, list) or not 1 <= len(roots) <= MAX_ROOTS:
        raise ConsumerError("invalid transcript roots")
    with ConsumerStore(store_path) as store:
        if store.recovery_required:
            raise ConsumerError("store recovery required")
        resolved_store = store.path.resolve(strict=True)
        checked = [_root(Path(root), resolved_store) for root in roots]
        targets = [root.resolve(strict=True) for root in checked]
        if len(set(map(str, targets))) != len(checked):
            raise ConsumerError("duplicate transcript root")
        script = BIN_DIR / "consumer-hook.py"
        if not script.is_file() or not Path(sys.executable).is_absolute():
            raise ConsumerError("hook interpreter or script unavailable")
        base = [sys.executable, "-B", str(script.resolve(strict=True))]
        def handler(event: str, timeout: int, with_roots: bool) -> dict:
            argv = base + [event, "--store", str(store.path)]
            if with_roots:
                for root, target_root in zip(checked, targets):
                    argv.extend(["--transcript-root", str(root),
                                 "--root-target", str(target_root)])
            return {"type": "command", "command": shlex.join(argv), "timeout": timeout}
        settings = {"hooks": {
            "UserPromptSubmit": [{"hooks": [handler("UserPromptSubmit", 5, False)]}],
            "Stop": [{"hooks": [handler("Stop", 10, True)]}],
        }}
        target = store.path / SETTINGS_FILE
        if target.is_symlink() or (target.exists() and (
                not target.is_file() or target.stat().st_nlink != 1 or
                target.stat().st_uid != os.getuid() or target.stat().st_mode & 0o077)):
            raise ConsumerError("unsafe hook settings file")
        data = canonical_bytes(settings) + b"\n"
        if target.exists() and read_regular(target, SMALL_LIMIT) == data:
            return target
        secure_replace_bytes(target, data)
        return target


def allowed_transcript(path_text: str, roots: list[Path],
                       targets: list[Path] | None = None) -> Path:
    """Require lexical and resolved containment before the importer opens a file."""
    if not isinstance(path_text, str) or not path_text.endswith(".jsonl"):
        raise ConsumerError("invalid transcript path")
    selected = Path(path_text)
    _path_text(selected)
    try:
        info = selected.lstat()
        resolved = selected.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ConsumerError("transcript unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ConsumerError("unsafe transcript file")
    for index, root in enumerate(roots):
        lexical = Path(root)
        resolved_root = lexical.resolve(strict=True)
        if targets is not None and resolved_root != targets[index]:
            raise ConsumerError("transcript root changed")
        if (selected != lexical and selected.is_relative_to(lexical) and
                resolved != resolved_root and resolved.is_relative_to(resolved_root)):
            if lexical.resolve(strict=True) != resolved_root:
                raise ConsumerError("transcript root changed")
            return resolved
    raise ConsumerError("transcript is outside selected roots")


def capture(store_path: Path, transcript_path: str, roots: list[Path],
            targets: list[Path] | None = None) -> dict | None:
    """Submit new transcript candidates for review; never publish them.

    Each transcript keeps at most one pending capture proposal: the new one
    holds every unapplied candidate of the whole transcript and replaces the
    earlier capture proposals of that transcript (``save_capture``).
    """
    selected = allowed_transcript(transcript_path, roots, targets)
    with ConsumerStore(store_path) as store:
        if store.recovery_required:
            raise ConsumerError("store recovery required")
        candidates, receipts, stats = collect_candidates(
            [selected], "claude-jsonl", store.manifest)
        existing = {fact["id"] for fact in store.facts}
        revoked = store.revoked_ids
        candidates = [fact for fact in candidates
                      if fact["id"] not in existing and fact["id"] not in revoked]
        if not candidates:
            return None
        stats["candidates"] = len(candidates)
        saved = store.save_capture(candidates, receipts, stats, str(selected))
        return {"digest": saved["digest"], "candidates": len(candidates),
                "replaced": saved["replaced"]}


def _sibling(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, BIN_DIR / filename)
    if spec is None or spec.loader is None:
        raise ConsumerError("recall module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def recall(store_path: Path, prompt: str, scratch_parent: Path) -> str | None:
    """Verify every captured record/event, then render production BM25 in scratch."""
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT:
        raise ConsumerError("invalid prompt")
    classifier = _sibling("_consumer_recall_classifier", "recall-classifier.py")
    if not classifier.classify(prompt, names=CUSTOMER_AUTHORITY_NAMES)[0]:
        return None
    store_path = Path(store_path)
    _path_text(store_path)
    _safe_dir(store_path)
    _safe_dir(store_path / "proposals")
    validator = ConsumerStore(store_path)
    if validator._transaction_temps():
        raise ConsumerError("store recovery required")
    _reject_cutover(store_path)
    scratch_parent = Path(scratch_parent)
    _path_text(scratch_parent)
    _safe_dir(scratch_parent)
    if (store_path / ".customer-journal.json").exists() or (store_path / ".customer-journal.json").is_symlink():
        raise ConsumerError("store recovery required")
    # Capturing only these public inputs deliberately avoids signing-key.
    observed = {}
    for name in ("customer.json", "facts.json", "signing-key.pub", "revocations.jsonl",
                 "purged-ids.jsonl"):
        path = store_path / name
        observed[name] = _stamp(path)
    manifest = _json(read_regular(store_path / "customer.json", SMALL_LIMIT))
    facts_data = read_regular(store_path / "facts.json", FACT_LIMIT)
    public_data = read_regular(store_path / "signing-key.pub", SMALL_LIMIT)
    rev_path = store_path / "revocations.jsonl"
    rev_data = read_regular(rev_path, FACT_LIMIT) if rev_path.exists() or rev_path.is_symlink() else b""
    purge_path = store_path / "purged-ids.jsonl"
    if observed["purged-ids.jsonl"] is not None and read_regular(purge_path, FACT_LIMIT).strip():
        raise ConsumerError("legacy purge ledger is unsupported")
    if (not isinstance(manifest, dict) or set(manifest) !=
            {"schema", "store_id", "key_id", "algorithm", "created_at"} or
            manifest["schema"] != "nockbrain-customer/v1" or
            not _uuid(manifest["store_id"]) or not _text(manifest["key_id"], 128) or
            not _timestamp(manifest["created_at"])):
        raise ConsumerError("invalid store manifest")
    facts = _json(facts_data)
    if not isinstance(facts, list):
        raise ConsumerError("invalid store facts")
    import _sign
    import _revoke
    public = _json(public_data)
    algorithm = manifest["algorithm"]
    if algorithm not in {_sign.ALG_ED25519, _sign.ALG_HMAC}:
        raise ConsumerError("invalid store verification key")
    material = "public_key" if algorithm == _sign.ALG_ED25519 else "secret"
    if (not isinstance(public, dict) or set(public) != {"alg", "key_id", material} or
            public["alg"] != algorithm or public["key_id"] != manifest["key_id"] or
            not isinstance(public[material], str) or
            not re.fullmatch(r"[0-9a-f]{64}", public[material])):
        raise ConsumerError("invalid store verification key")
    with tempfile.TemporaryDirectory(prefix="nockbrain-recall-",
                                     dir=scratch_parent) as scratch_name:
        scratch = Path(scratch_name)
        os.chmod(scratch, 0o700)
        for name, data in (("facts.json", facts_data), ("signing-key.pub", public_data),
                           ("revocations.jsonl", rev_data)):
            path = scratch / name
            with path.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
        key = _sign.load_public_key(scratch / "signing-key.pub")
        if key.key_id != manifest.get("key_id") or key.alg != manifest.get("algorithm"):
            raise ConsumerError("store verification key mismatch")
        validator._manifest = manifest
        validator._key = key
        validator._validate_facts(facts, require_attestation=True)
        events = validator._parse_events(rev_data)
        validator._validate_lifecycle(facts, events)
        audit = _revoke.audit(facts, events, key)
        if (audit["invalid_events"] or audit["foreign_key_events"] or
                audit["resurrected"] or audit["unattested_superseded"]):
            raise ConsumerError("revocation verification failed")
        if (validator._transaction_temps() or
                any(_stamp(store_path / name) != stamp for name, stamp in observed.items()) or
                (store_path / ".customer-journal.json").exists() or
                (store_path / ".customer-journal.json").is_symlink()):
            raise ConsumerError("store snapshot changed")
        _reject_cutover(store_path)
        # No inherited configuration; production selection can only see scratch.
        os.environ["NOCKBRAIN_SIGNING_KEY"] = str(scratch / "_no-private-key")
        os.environ["NOCKBRAIN_SIGNING_PUB"] = str(scratch / "signing-key.pub")
        os.environ["NOCKBRAIN_STORE"] = "json"
        budget = _sibling("_consumer_budget_recall", "budget-recall.py")
        rendered = budget.budget_recall(
            prompt, scratch / "facts.json", budget=800,
            insights_file=None, graph_expand=False, semantic=False,
            strict_verify=True, agent_scope=None)
        return rendered or None


def _reject_cutover(store_path: Path) -> None:
    for name in ("store-v2", "brain.db"):
        path = store_path / name
        if path.exists() or path.is_symlink():
            raise ConsumerError("SQLite store is unsupported")


def _stamp(path: Path) -> tuple | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ConsumerError("unsafe store snapshot file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid)
