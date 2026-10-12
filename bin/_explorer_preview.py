#!/usr/bin/env python3
"""Isolated, read-only production recall for the Memory Explorer.

The public function launches this file as a child. Only completed snapshot
inputs are copied into its private working directory; recall's caches and
degradation logs can therefore never land beside the selected source store.
"""
from __future__ import annotations

import importlib.util
import json
import math
import os
from pathlib import Path
import stat
# Fixed sibling worker with a fixed interpreter and explicit argv; no shell.
import subprocess  # nosec B404
import sys
import tempfile


MAX_QUERY = 2000
MAX_BUDGET = 1500
MAX_INPUT = 32 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
SNAPSHOT_FILES = ("facts.json", "insights.json", "revocations.jsonl", "signing-key.pub")


class PreviewError(ValueError):
    """A safe message that may be shown to the local client."""


def _validate_request(query: str, budget: int) -> None:
    if not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY:
        raise PreviewError("Preview query must contain 1 to 2000 characters.")
    if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= MAX_BUDGET:
        raise PreviewError("Preview budget must be an integer from 1 to 1500.")


def _copy_snapshot_file(source: Path, target: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(source, flags)
    except FileNotFoundError:
        return
    except OSError:
        raise PreviewError("Preview snapshot is unavailable.") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INPUT:
            raise PreviewError("Preview snapshot is unavailable.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_INPUT + 1)
        after = os.fstat(fd)
        if (len(data) > MAX_INPUT or len(data) != before.st_size or
                (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size) !=
                (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size)):
            raise PreviewError("Preview snapshot is unavailable.")
        with target.open("xb") as output:
            os.chmod(target, 0o600)
            output.write(data)
    finally:
        os.close(fd)


def run_preview(snapshot_dir: Path, query: str, budget: int = 800, *,
                timeout: float = 5.0) -> dict:
    """Run production classifier and BM25 selection against one snapshot."""
    _validate_request(query, budget)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise PreviewError("Preview timeout is invalid.")
    try:
        # Snapshot input belongs to Explorer's scratch root; place this child
        # there rather than honoring a hostile TMPDIR or touching the source.
        with tempfile.TemporaryDirectory(
                prefix="nock-explorer-preview-", dir=Path(snapshot_dir).parent) as root_name:
            root = Path(root_name)
            os.chmod(root, 0o700)
            child_home = root / "home"
            child_home.mkdir(mode=0o700)
            copied = root / "snapshot"
            copied.mkdir(mode=0o700)
            for name in SNAPSHOT_FILES:
                _copy_snapshot_file(Path(snapshot_dir) / name, copied / name)
            env = {
                "HOME": str(child_home),
                "NOCKBRAIN_STORE": "json",
                "NOCKBRAIN_SIGNING_KEY": str(copied / "_no-private-key"),
                "NOCKBRAIN_SIGNING_PUB": str(copied / "signing-key.pub"),
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUTF8": "1",
            }
            request = json.dumps({"query": query, "budget": budget}, ensure_ascii=True)
            try:
                # sys.executable and the sibling script path are fixed by this module.
                completed = subprocess.run(  # nosec B603
                    [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", str(copied)],
                    input=request, text=True, encoding="utf-8", errors="replace",
                    capture_output=True, timeout=timeout, env=env, check=False,
                )
            except subprocess.TimeoutExpired:
                raise PreviewError("Preview timed out.") from None
            if completed.returncode != 0 or len(completed.stdout) > MAX_OUTPUT:
                raise PreviewError("Preview could not be completed.")
            try:
                result = json.loads(completed.stdout)
            except (ValueError, TypeError):
                raise PreviewError("Preview could not be completed.") from None
            if not isinstance(result, dict):
                raise PreviewError("Preview could not be completed.")
            if "error" in result:
                # Worker errors are a closed set of fixed strings.
                message = result["error"]
                if message not in {"Preview snapshot is unreadable.",
                                   "Preview could not be completed."}:
                    message = "Preview could not be completed."
                raise PreviewError(message)
            return result
    except PreviewError:
        raise
    except (OSError, ValueError):
        raise PreviewError("Preview could not be completed.") from None


def _load_script(name: str):
    path = Path(__file__).resolve().parent / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        raise RuntimeError("module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _reject_constant(_value):
    raise ValueError("non-finite number")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite number")
    return number


def _validate_json_inputs(directory: Path) -> dict:
    loaded = {}
    for name in ("facts.json", "insights.json"):
        path = directory / name
        if not path.exists():
            loaded[name] = []
            continue
        try:
            with path.open("r", encoding="utf-8") as stream:
                records = json.load(stream, parse_constant=_reject_constant,
                                    parse_float=_finite_float)
            if not isinstance(records, list):
                raise ValueError("wrong root")
            loaded[name] = records
        except (OSError, UnicodeError, ValueError, RecursionError):
            raise PreviewError("Preview snapshot is unreadable.") from None
    events = []
    revocations = directory / "revocations.jsonl"
    if revocations.exists():
        try:
            with revocations.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if line.strip():
                        event = json.loads(line, parse_constant=_reject_constant,
                                           parse_float=_finite_float)
                        if not isinstance(event, dict):
                            raise ValueError("invalid event")
                        events.append(event)
        except (OSError, UnicodeError, ValueError, RecursionError):
            raise PreviewError("Preview snapshot is unreadable.") from None
    loaded["revocations.jsonl"] = events
    return loaded


def _worker(directory: Path) -> dict:
    request = json.load(sys.stdin)
    if not isinstance(request, dict):
        raise PreviewError("Preview could not be completed.")
    query = request.get("query")
    budget = request.get("budget")
    _validate_request(query, budget)
    loaded = _validate_json_inputs(directory)
    classifier = _load_script("recall-classifier.py")
    recall = _load_script("budget-recall.py")
    import _sign
    import _facts
    import _revoke
    eligible, reason, categories = classifier.classify(query)
    key, key_error = _sign.resolve_verify_key()
    notices = []
    if key_error:
        notices.append("Verification key is invalid; preview is unverified.")
    elif key is None:
        notices.append("Verification key is missing; preview is unverified.")
    fact_records = _facts.filter_valid_facts(
        loaded["facts.json"], source="preview-facts",
        required_fields=_facts.RECALL_ITEM_FIELDS,
    )
    insight_records = _facts.filter_valid_facts(
        loaded["insights.json"], source="preview-insights",
        required_fields=_facts.RECALL_ITEM_FIELDS,
    )
    malformed = (len(loaded["facts.json"]) + len(loaded["insights.json"]) -
                 len(fact_records) - len(insight_records))
    if malformed:
        notices.append(f"{malformed} malformed record(s) were skipped.")
    if key is not None:
        for records in (fact_records, insight_records):
            if not records:
                continue
            try:
                report = _sign.verify_facts(records, key)
                if report["tampered"]:
                    notices.append(f"{report['tampered']} tampered record(s) were excluded.")
                if report["unsigned"]:
                    notices.append(f"{report['unsigned']} unsigned record(s) are allowed in this preview.")
                if report["parent_suspect"]:
                    notices.append(f"{report['parent_suspect']} parent-suspect record(s) are allowed in this preview.")
            except Exception:
                notices.append("Some record verification could not be completed.")
        try:
            audit = _revoke.audit(fact_records, loaded["revocations.jsonl"], key)
            if audit["invalid_events"]:
                notices.append(f"{audit['invalid_events']} invalid revocation event(s) were ignored.")
            if audit["resurrected"]:
                notices.append(f"{len(audit['resurrected'])} revoked record(s) were excluded.")
        except Exception:
            notices.append("Revocation verification could not be completed.")
    facts = directory / "facts.json"
    insights = directory / "insights.json"
    selection = recall.select_recall(
        query, facts if facts.exists() else None, budget,
        include_superseded=False,
        insights_file=insights if insights.exists() else None,
        graph_expand=False, max_per_date=4, strict_verify=False,
        semantic=False, agent_scope=None,
    )
    if selection is None:
        included = []
        rendered = ""
        tokens_used = 0
        matches = 0
        truncated = False
    else:
        included = selection["included"]
        matches = len(selection["results"])
        tokens_used = selection["tokens_used"]
        truncated = selection["truncated"]
        lines = [f"Memory recall ({matches} matches, budget {budget} tokens):"]
        for fact in included:
            lines.append(recall.format_fact(fact, selection["query_terms"]))
        remaining = matches - len(included)
        if truncated and remaining > 0:
            lines.append(f"[...{remaining} more results truncated by budget]")
        lines.append(f"[{len(included)} item(s), ~{tokens_used} tokens]")
        rendered = "\n\n".join(lines)
    items = [
        {"id": str(fact.get("id", "")), "kind": str(fact.get("kind", "")),
         "content": str(fact.get("content", "")),
         "source_date": str(fact.get("source_date", ""))}
        for fact in included
    ]
    return {
        "classifier": {"eligible": eligible, "reason": reason, "categories": categories},
        "settings": {"budget": budget, "semantic": False, "graph": False,
                     "max_per_date": 4, "strict_verify": False, "agent_scope": None},
        "items": items, "rendered": rendered, "tokens_used": tokens_used,
        "matches": matches, "truncated": truncated, "notices": notices,
    }


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != "--worker":
        return 2
    try:
        result = _worker(Path(sys.argv[2]))
    except PreviewError as exc:
        result = {"error": str(exc)}
    except Exception:
        result = {"error": "Preview could not be completed."}
    sys.stdout.write(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
