#!/usr/bin/env python3
"""NockBrain: explicit, reviewed memory-store setup and import commands."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
# Fixed sibling script and explicit argv; never a shell.
import subprocess  # nosec B404
import sys

# A selected source may live in this checkout. Imports must not create pyc files.
sys.dont_write_bytecode = True
BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from _consumer_import import collect_candidates
from _consumer_store import ConsumerError, ConsumerStore, init_store

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        # argparse normally echoes untrusted arguments, including terminal controls.
        raise ValueError("invalid command arguments; use --help")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description="NockBrain: explicit memory store setup and reviewed imports")
    modes = parser.add_subparsers(dest="mode", parser_class=_Parser)
    descriptions = {
        "init": "Create a fresh, private memory store",
        "status": "Show store health, counts, and next commands",
        "propose": "Import selected notes into the review queue",
        "pending": "List saved proposals and whether they are stale",
        "review": "Read a complete proposal without applying it",
        "apply": "Accept the exact reviewed proposal digest",
        "discard": "Delete one saved proposal",
        "correct": "Propose replacing one fact with a single imported candidate",
        "forget": "Propose erasing one fact and clearing saved proposals",
        "recover": "Finish an interrupted, previously accepted memory operation",
        "setup-hooks": "Generate opt-in Claude Code session settings",
        "open": "Open the local, read-only Memory Explorer",
    }
    for mode, description in descriptions.items():
        command = modes.add_parser(mode, help=description, description=description)
        command.add_argument("--store", required=True, metavar="ABSOLUTE_PATH")
        if mode == "propose":
            command.add_argument("--format", required=True, choices=("markdown", "claude-jsonl"))
            command.add_argument("--source", required=True, action="append", metavar="ABSOLUTE_FILE")
        if mode in ("review", "apply", "discard"):
            command.add_argument("--proposal", required=True, metavar="SHA256")
        if mode in ("correct", "forget"):
            command.add_argument("--fact", required=True, metavar="FACT_ID")
        if mode == "correct":
            command.add_argument("--replacement-proposal", required=True, metavar="SHA256")
        if mode == "setup-hooks":
            command.add_argument("--transcript-root", required=True, action="append",
                                 metavar="ABSOLUTE_DIRECTORY")
    return parser


def _safe_path(value: str) -> Path:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ConsumerError("path contains terminal controls")
    return Path(value)


def _command(mode: str, store: str, digest: str | None = None) -> str:
    args = [sys.executable, str(Path(__file__).resolve()), mode, "--store", store]
    if digest is not None:
        args.extend(["--proposal", digest])
    return " ".join(shlex.quote(arg) for arg in args)


def _emit(value: dict, *, pretty: bool = False) -> None:
    print(json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                     indent=2 if pretty else None))


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        if args.mode is None:
            parser.print_help()
            return 0
        store_path = _safe_path(args.store)
        if not store_path.is_absolute():
            raise ConsumerError("store path must be absolute")
        if args.mode == "propose":
            sources = [_safe_path(value) for value in args.source]
        if args.mode in ("review", "apply", "discard") and not _DIGEST.fullmatch(args.proposal):
            raise ConsumerError("proposal digest must be full SHA-256")
        if args.mode == "init":
            manifest = init_store(store_path)
            _emit({"store_id": manifest["store_id"], "algorithm": manifest["algorithm"],
                   "store": args.store,
                   "next": "Select explicit notes, then run propose --store PATH --format markdown --source FILE.",
                   "status_command": _command("status", args.store),
                   "open_command": _command("open", args.store)})
        elif args.mode == "open":
            # Explorer reads only the selected public snapshot. Its own server
            # owns shutdown, browser opening and the per-launch capability URL.
            environment = dict(os.environ, NOCKBRAIN_STORE="json",
                               PYTHONDONTWRITEBYTECODE="1")
            return subprocess.call(  # nosec B603
                [sys.executable, "-B", str(BIN_DIR / "explore-memory.py"),
                 "--store", str(store_path), "--open"], env=environment)
        elif args.mode == "setup-hooks":
            from _consumer_hooks import setup_hooks
            roots = [_safe_path(value) for value in args.transcript_root]
            settings = setup_hooks(store_path, roots)
            _emit({"settings": str(settings),
                   "launch_command": "claude --settings " + shlex.quote(str(settings)),
                   "pending_command": _command("pending", args.store),
                   "existing_hooks": "Other Claude hooks can still run; check /hooks to see what else adds context.",
                   "capture": "Pending proposals only; review and apply separately."})
        elif args.mode == "propose":
            with ConsumerStore(store_path) as store:
                candidates, receipts, stats = collect_candidates(sources, args.format, store.manifest)
                digest = store.save_proposal(candidates, receipts, stats)
            _emit({"candidates": len(candidates), "proposal": digest, "stats": stats,
                   "review_command": _command("review", args.store, digest)})
        elif args.mode == "review":
            with ConsumerStore(store_path) as store:
                proposal = store.read_proposal(args.proposal)
                result = {"proposal": args.proposal, "review": proposal,
                          "stale": proposal["generation"] != store.generation,
                          "recovery_required": store.recovery_required,
                          "apply_command": _command("apply", args.store, args.proposal)}
                if "fact_id" in proposal and not store.recovery_required:
                    result["target"] = next((fact for fact in store.facts
                                             if fact["id"] == proposal["fact_id"]), None)
                if proposal.get("action") == "forget":
                    result["effect"] = ("Remove the selected record and all saved proposals. "
                                        "Keep its signed ID revocation to prevent exact reimport. "
                                        "Original sources, backups, other records and open Explorer "
                                        "snapshots are outside this erasure.")
            _emit(result, pretty=True)
        elif args.mode == "apply":
            with ConsumerStore(store_path) as store:
                result = store.apply_proposal(args.proposal)
            _emit(result)
        elif args.mode in ("correct", "forget"):
            with ConsumerStore(store_path) as store:
                if args.mode == "correct":
                    digest = store.propose_correction(args.fact, args.replacement_proposal)
                else:
                    digest = store.propose_forget(args.fact)
            _emit({"action": args.mode, "proposal": digest,
                   "review_command": _command("review", args.store, digest)})
        elif args.mode == "discard":
            with ConsumerStore(store_path) as store:
                store.discard_proposal(args.proposal)
            _emit({"discarded": args.proposal})
        elif args.mode == "pending":
            with ConsumerStore(store_path) as store:
                proposals = store.pending_proposals()
            _emit({"proposals": proposals})
        elif args.mode == "recover":
            with ConsumerStore(store_path) as store:
                result = store.recover()
            _emit(result)
        elif args.mode == "status":
            with ConsumerStore(store_path) as store:
                result = store.status()
            result["commands"] = {mode: _command(mode, args.store)
                                  for mode in ("pending", "open", "recover")}
            _emit(result, pretty=True)
        return 0
    except ConsumerError as exc:
        _emit({"error": str(exc)})
        return 2
    except ValueError:
        _emit({"error": "invalid command arguments; use --help"})
        return 2
    except Exception:
        _emit({"error": "NockBrain operation failed"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
