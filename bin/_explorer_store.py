"""Bounded, read-only snapshots for the optional local Memory Explorer.

The selected directory is never used as a write target. This module has no
import-time store access and does not participate in the recall hook.
"""
from __future__ import annotations

import json
import math
import os
import shutil
import stat
import tempfile
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from _facts import fact_currently_valid
from _revoke import audit, sign_revocation, verify_revocation
from _sign import ALG_HMAC, SigningKey, load_public_key, sign_facts, verify_facts
from _store import secure_replace_bytes, secure_write_json

FILE_LIMIT = 32 * 1024 * 1024
TOTAL_LIMIT = 64 * 1024 * 1024
INPUTS = ("facts.json", "insights.json", "revocations.jsonl", "signing-key.pub")
# Secure mkdtemp creates owner-only scratch outside the selected source;
# fixed bases prevent hostile TMPDIR from redirecting writes into that source.
_TEMP_BASES = (Path("/tmp"), Path("/var/tmp"))  # nosec B108
DETAIL_FIELDS = (
    "source_date", "source_time", "valid_at", "invalid_at", "valid_from",
    "valid_to", "confidence", "evidence", "source", "parents", "parent_fact_ids",
    "parent_revision_ids", "superseded_by", "memory_id", "revision_id",
    "revokes_revision_ids", "scope", "category", "verify_before_act",
    "promotion_batch_digest",
)


class ExplorerError(ValueError):
    """Safe, user-visible error without selected-store bytes or paths."""


class _Drift(Exception):
    pass


def _stamp(path: Path):
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise ExplorerError("A selected input could not be inspected.") from None
    if not stat.S_ISREG(st.st_mode):
        raise ExplorerError("A selected input is a symlink or special file.")
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode)


def _private_inode(path: Path):
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise ExplorerError("The selected store could not be inspected.") from None
    return (st.st_dev, st.st_ino) if stat.S_ISREG(st.st_mode) else None


def _read_one(path: Path, before, private_path=None):
    if before is None:
        return None
    if before[2] > FILE_LIMIT:
        raise ExplorerError("A selected input exceeds the 32 MiB file limit.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise _Drift() from None
    except OSError:
        raise ExplorerError("A selected input could not be read.") from None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise ExplorerError("A selected input is a symlink or special file.")
        if private_path is not None and (fst.st_dev, fst.st_ino) == _private_inode(private_path):
            raise ExplorerError("A private signing key cannot be used for verification.")
        if (fst.st_dev, fst.st_ino, fst.st_size, fst.st_mtime_ns, fst.st_mode) != before:
            raise _Drift()
        pieces = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, FILE_LIMIT + 1 - total))
            if not chunk:
                break
            pieces.append(chunk)
            total += len(chunk)
            if total > FILE_LIMIT:
                raise ExplorerError("A selected input exceeds the 32 MiB file limit.")
        if total != before[2] or _stamp(path) != before:
            raise _Drift()
        return b"".join(pieces)
    except OSError:
        raise ExplorerError("A selected input could not be read.") from None
    finally:
        os.close(fd)


def _sqlite_marker_present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        raise ExplorerError("The selected store could not be inspected.") from None


def _capture(paths, private_path, marker_path):
    for attempt in range(2):
        try:
            if _sqlite_marker_present(marker_path):
                raise ExplorerError("SQLite stores are unsupported by Memory Explorer.")
            before = {name: _stamp(path) for name, path in paths.items()}
            if sum(stamp[2] for stamp in before.values() if stamp) > TOTAL_LIMIT:
                raise ExplorerError("Selected inputs exceed the 64 MiB snapshot limit.")
            data = {name: _read_one(path, before[name], private_path if name == "signing-key.pub" else None)
                    for name, path in paths.items()}
            if _sqlite_marker_present(marker_path):
                raise ExplorerError("SQLite stores are unsupported by Memory Explorer.")
            if any(_stamp(path) != before[name] for name, path in paths.items()):
                raise _Drift()
            return data
        except _Drift:
            if attempt:
                raise ExplorerError("A stable snapshot could not be obtained.") from None
    raise ExplorerError("A stable snapshot could not be obtained.")


def _demo_fact(fid, kind, content, *, status="current", date="2026-09-20", **extra):
    record = {
        "id": fid, "kind": kind, "content": content, "status": status,
        "confidence": 0.9, "source_date": date,
        "evidence": ["Fictional Willow Workshop planning note"],
    }
    record.update(extra)
    return record


def _make_demo(root: Path):
    key = SigningKey(ALG_HMAC, hmac_secret=os.urandom(32))
    facts = [
        _demo_fact("willow-delivery-old", "decision", "Willow Workshop first chose Wednesday delivery by van.",
                   status="superseded", superseded_by="willow-delivery-new", invalid_at="2026-09-19T12:00:00Z"),
        _demo_fact("willow-delivery-new", "decision", "Willow Workshop decided to offer local delivery on Fridays by cargo bicycle; shoppers choose a two-hour window."),
        _demo_fact("willow-delivery-correction", "correction", "Correction: Friday delivery starts at 10 a.m., not 9 a.m."),
        _demo_fact("willow-packaging", "preference", "Willow Workshop prefers recycled paper packaging."),
        _demo_fact("willow-orders", "fact", "Willow Workshop closes custom orders on Tuesdays."),
        _demo_fact("willow-pickup", "decision", "In-store pickup remains free for all local shoppers."),
        _demo_fact("willow-samples", "fact", "Sample kits are prepared in batches of twelve."),
        _demo_fact("willow-hours", "fact", "The fictional workshop opens Thursday through Sunday."),
    ]
    sign_facts(facts, key)
    facts.append(_demo_fact("willow-unsigned-note", "note", "Unsigned draft: ask shoppers whether evening pickup helps."))
    insights = [_demo_fact("willow-delivery-insight", "insight", "Delivery planning favors predictable Friday bicycle routes and chosen windows.")]
    sign_facts(insights, key)
    secure_write_json(root / "facts.json", facts, ensure_ascii=False)
    secure_write_json(root / "insights.json", insights, ensure_ascii=False)
    event = sign_revocation(key, superseded_id="willow-delivery-old",
                            superseding_id="willow-delivery-new", reason="fictional delivery change")
    secure_replace_bytes(root / "revocations.jsonl", (json.dumps(event) + "\n").encode())
    secure_write_json(root / "signing-key.pub", {
        "alg": ALG_HMAC, "key_id": key.key_id, "secret": key._hmac_secret.hex()
    })


def _json_list(data, filename, notices):
    if data is None:
        return [], "missing"
    if not data:
        notices.append(f"{filename} is empty and cannot be parsed.")
        return [], "unreadable"
    try:
        value = json.loads(data.decode("utf-8"), parse_constant=_reject_nonfinite, parse_float=_finite_float)
    except (UnicodeError, ValueError, RecursionError):
        notices.append(f"{filename} could not be parsed.")
        return [], "unreadable"
    if not isinstance(value, list):
        notices.append(f"{filename} must contain a list.")
        return [], "unreadable"
    return value, "empty" if not value else "readable"


def _valid_record(value):
    if not isinstance(value, dict):
        return False
    for name in ("id", "kind", "content", "status"):
        if not isinstance(value.get(name), str) or not value[name].strip():
            return False
    for name in ("source_date", "source_time", "superseded_by"):
        if name in value and value[name] is not None and not isinstance(value[name], str):
            return False
    for name in ("parents", "parent_fact_ids", "parent_revision_ids", "revokes_revision_ids"):
        if name in value and (not isinstance(value[name], list) or any(not isinstance(item, str) for item in value[name])):
            return False
    if "attestation" in value and not isinstance(value["attestation"], dict):
        return False
    if "evidence" in value and not isinstance(value["evidence"], (str, list, dict)):
        return False
    if "confidence" in value and (isinstance(value["confidence"], bool) or not isinstance(value["confidence"], (int, float))):
        return False
    if "confidence" in value:
        try:
            if not math.isfinite(value["confidence"]):
                return False
        except OverflowError:
            return False
    return True


def _reject_nonfinite(_value):
    raise ValueError("non-finite JSON number")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _scratch_root(selected_store):
    """Create scratch outside the selected source, ignoring TMPDIR/TEMP/TMP."""
    source = Path(os.path.realpath(os.path.abspath(selected_store))) if selected_store is not None else None
    for candidate in _TEMP_BASES:
        base = Path(os.path.realpath(candidate))
        if source is not None and (base == source or base.is_relative_to(source)):
            continue
        if not base.is_dir():
            continue
        root = None
        try:
            root = Path(tempfile.mkdtemp(prefix="nock-explorer-", dir=base))
            os.chmod(root, 0o700)
            return root
        except OSError:
            if root is not None:
                shutil.rmtree(root, ignore_errors=True)
            continue
    raise ExplorerError("No safe temporary directory is available.")


class ExplorerStore:
    def __init__(self, store: Path | None = None, *, demo: bool = False,
                 verify_key: Path | None = None):
        if demo == (store is not None) or (demo and verify_key is not None):
            raise ExplorerError("Select exactly one mode: demo or store.")
        if not demo and os.environ.get("NOCKBRAIN_STORE", "").lower() == "sqlite":
            raise ExplorerError("SQLite stores are unsupported by Memory Explorer.")
        self._demo = demo
        self._store = Path(store) if store is not None else None
        self._verify_key = Path(verify_key) if verify_key is not None else None
        self._root = _scratch_root(self._store)
        self.snapshot_dir = self._root
        self.snapshot_id = ""
        self._summary = {}
        self._records = []
        self._detail = {}
        try:
            if demo:
                self._store = self._root / "demo-source"
                self._store.mkdir(mode=0o700)
                _make_demo(self._store)
            self.refresh()
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        shutil.rmtree(self._root, ignore_errors=True)

    def _paths(self):
        root = self._store
        try:
            rst = root.lstat()
        except FileNotFoundError:
            rst = None
        except OSError:
            raise ExplorerError("The selected store could not be inspected.") from None
        if rst is not None and not stat.S_ISDIR(rst.st_mode):
            raise ExplorerError("The selected store must be a regular directory.")
        if _sqlite_marker_present(root / "store-v2"):
            raise ExplorerError("SQLite stores are unsupported by Memory Explorer.")
        key_path = self._verify_key or (root / "signing-key.pub")
        private = root / "signing-key"
        if os.path.abspath(key_path) == os.path.abspath(private):
            raise ExplorerError("A private signing key cannot be used for verification.")
        candidate_stamp = _stamp(key_path)
        # Inspect only metadata here. The private file may itself be a
        # symlink; it is never an input and must never be opened.
        private_stamp = _private_inode(private)
        if candidate_stamp and private_stamp and candidate_stamp[:2] == private_stamp:
            raise ExplorerError("A private signing key cannot be used for verification.")
        return {"facts.json": root / "facts.json", "insights.json": root / "insights.json",
                "revocations.jsonl": root / "revocations.jsonl", "signing-key.pub": key_path}

    def refresh(self) -> dict:
        data = _capture(self._paths(), self._store / "signing-key", self._store / "store-v2")
        generation = self._root / ("generation-" + uuid.uuid4().hex)
        generation.mkdir(mode=0o700)
        try:
            for name, contents in data.items():
                if contents is not None:
                    if name == "signing-key.pub":
                        try:
                            document = json.loads(contents.decode("utf-8"), parse_constant=_reject_nonfinite, parse_float=_finite_float)
                        except (UnicodeError, ValueError, RecursionError):
                            document = None
                        if isinstance(document, dict) and "private_key" in document:
                            # Reject a private document without copying its
                            # material into the preview generation.
                            contents = b"{}"
                    secure_replace_bytes(generation / name, contents)
            summary, records, details = self._build(generation, data)
            if _sqlite_marker_present(self._store / "store-v2"):
                raise ExplorerError("SQLite stores are unsupported by Memory Explorer.")
        except BaseException:
            shutil.rmtree(generation, ignore_errors=True)
            raise
        previous = self.snapshot_dir
        self.snapshot_dir = generation
        self.snapshot_id = summary["snapshot_id"]
        self._summary, self._records, self._detail = summary, records, details
        if previous != self._root:
            shutil.rmtree(previous, ignore_errors=True)
        return self.summary()

    def _build(self, generation, data):
        notices = []
        facts, facts_state = _json_list(data["facts.json"], "facts.json", notices)
        insights, insights_state = _json_list(data["insights.json"], "insights.json", notices)
        files = {"facts.json": {"state": facts_state, "count": len(facts)},
                 "insights.json": {"state": insights_state, "count": len(insights)}}
        rev_data = data["revocations.jsonl"]
        events = []
        if rev_data is None:
            rev_state = "missing"
        elif not rev_data:
            rev_state = "empty"
        else:
            rev_state = "readable"
            try:
                for line in rev_data.decode("utf-8").splitlines():
                    if not line.strip():
                        continue
                    event = json.loads(line, parse_constant=_reject_nonfinite, parse_float=_finite_float)
                    if not isinstance(event, dict):
                        raise ValueError()
                    events.append(event)
            except (UnicodeError, ValueError, RecursionError):
                notices.append("revocations.jsonl contains malformed events; revocation audit is unavailable.")
                events, rev_state = [], "unreadable"
        files["revocations.jsonl"] = {"state": rev_state, "count": len(events)}
        key = None
        key_data = data["signing-key.pub"]
        if key_data is None:
            key_state = "missing"
            notices.append("Verification key is missing; signatures are unavailable.")
        else:
            try:
                key_doc = json.loads(key_data.decode("utf-8"), parse_constant=_reject_nonfinite, parse_float=_finite_float)
                if not isinstance(key_doc, dict) or "private_key" in key_doc:
                    raise ValueError()
                key = load_public_key(generation / "signing-key.pub")
                key_state = "available"
            except (OSError, UnicodeError, ValueError, RuntimeError, KeyError, TypeError, RecursionError) as exc:
                key_state = "invalid"
                if isinstance(exc, RuntimeError) and "cryptography is unavailable" in str(exc):
                    notices.append("Ed25519 verification requires optional cryptography; signatures are unavailable.")
                else:
                    notices.append("Verification key is invalid or unsupported; signatures are unavailable.")
        files["signing-key.pub"] = {"state": key_state, "count": 1 if key else 0}
        all_rows = []
        for collection, values in (("facts", facts), ("insights", insights)):
            seen = Counter(value.get("id") for value in values if isinstance(value, dict) and isinstance(value.get("id"), str))
            if any(count > 1 for count in seen.values()):
                notices.append(f"{collection} contains duplicate identifiers; use row handles for details.")
            safe = [value for value in values if _valid_record(value)]
            status_by_object = {}
            if key is not None and safe:
                try:
                    verification = verify_facts(safe, key)
                    status_by_object = {id(value): result["status"] for value, result in zip(safe, verification["statuses"])}
                except Exception:
                    notices.append(f"{collection} contains records the verifier could not process.")
                    for value in safe:
                        try:
                            result = verify_facts([value], key)["statuses"][0]["status"]
                        except Exception:
                            result = "invalid"
                        status_by_object[id(value)] = result
            for index, raw in enumerate(values):
                valid = _valid_record(raw)
                if not valid:
                    notices.append(f"{collection} row {index + 1} is malformed.")
                value = raw if isinstance(raw, dict) else {}
                copied = dict(value)
                source_date = copied.get("source_date")
                if not isinstance(source_date, str) or not source_date:
                    source_time = copied.get("source_time")
                    source_date = source_time[:10] if isinstance(source_time, str) and len(source_time) >= 10 else ""
                status = value.get("status") if isinstance(value.get("status"), str) else "invalid"
                row = {
                    "handle": f"{collection}:{index}", "collection": collection,
                    "id": value.get("id") if isinstance(value.get("id"), str) else "",
                    "kind": value.get("kind") if isinstance(value.get("kind"), str) else "",
                    "content": value.get("content") if isinstance(value.get("content"), str) else "",
                    "status": status, "source_date": source_date,
                    "confidence": value.get("confidence") if isinstance(value.get("confidence"), (int, float)) and not isinstance(value.get("confidence"), bool) else None,
                    "verification": ("invalid" if not valid else
                                     "unsigned" if "attestation" not in value else
                                     "unavailable" if key is None else
                                     status_by_object.get(id(raw), "invalid")),
                    "details": {field: value[field] for field in DETAIL_FIELDS if field in value},
                }
                if not valid:
                    row["lifecycle"] = "invalid"
                elif status == "superseded":
                    row["lifecycle"] = "superseded"
                elif status != "current" or not fact_currently_valid(copied):
                    row["lifecycle"] = "inactive"
                else:
                    row["lifecycle"] = "current"
                all_rows.append(row)
        if key is not None and rev_state != "unreadable":
            safe_facts = [value for value in facts if _valid_record(value)]
            report = audit(safe_facts, events, key)
            trusted_revoked_ids = {
                event.get("superseded_id") for event in events
                if verify_revocation(event, key) and isinstance(event.get("superseded_id"), str)
            }
            resurrected_rows = 0
            for row in all_rows:
                if (row["collection"] == "facts" and row["id"] in trusted_revoked_ids
                        and row["lifecycle"] not in ("superseded", "invalid")):
                    row["lifecycle"] = "revoked"
                    resurrected_rows += 1
            if resurrected_rows:
                notices.append(f"{resurrected_rows} fact row(s) conflict with trusted revocations.")
            if report["invalid_events"]:
                notices.append(f"{report['invalid_events']} revocation event(s) failed verification.")
            if report["unattested_superseded"]:
                notices.append(f"{len(report['unattested_superseded'])} superseded fact(s) lack trusted revocations.")
        elif events:
            notices.append("Revocation audit is unavailable without a valid verification key.")
        id_handles = {}
        for row in all_rows:
            if row["id"]:
                id_handles.setdefault(row["id"], []).append(row["handle"])
        details = {}
        for row in all_rows:
            links = []
            target = row["details"].get("superseded_by")
            if isinstance(target, str):
                links = [{"id": target, "handle": handle, "relation": "superseded_by"}
                         for handle in id_handles.get(target, [])]
            details[row["handle"]] = dict(row, links=links)
        if facts_state == "unreadable" or insights_state == "unreadable" or rev_state == "unreadable":
            state = "unreadable"
        else:
            state = facts_state
        verification_counts = dict(Counter(row["verification"] for row in all_rows))
        summary = {
            "snapshot_id": uuid.uuid4().hex,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "mode": "demo" if self._demo else "store",
            "store": "Synthetic Willow Workshop demo" if self._demo else str(self._store),
            "state": state,
            "counts": {"facts": len(facts), "insights": len(insights)},
            "kinds": sorted({row["kind"] for row in all_rows if row["kind"]}),
            "verification": {"state": key_state, "counts": verification_counts},
            "files": files, "notices": notices,
        }
        return summary, all_rows, details

    def summary(self) -> dict:
        return json.loads(json.dumps(self._summary))

    def list_records(self, *, query='', kind='', lifecycle='current', collection='', offset=0, limit=50) -> dict:
        if not isinstance(query, str) or not isinstance(kind, str) or not isinstance(lifecycle, str) or not isinstance(collection, str):
            raise ExplorerError("Invalid record filter.")
        if lifecycle not in ("current", "superseded", "inactive", "revoked", "invalid", "all"):
            raise ExplorerError("Invalid lifecycle filter.")
        if collection not in ("", "facts", "insights"):
            raise ExplorerError("Invalid collection filter.")
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ExplorerError("Invalid pagination parameters.")
        needle = query.casefold()
        rows = [row for row in self._records
                if (lifecycle == "all" or row["lifecycle"] == lifecycle)
                and (not collection or row["collection"] == collection)
                and (not kind or row["kind"] == kind)
                and (not needle or needle in row["id"].casefold() or needle in row["content"].casefold())]
        return {"snapshot_id": self.snapshot_id,
                "items": [{k: v for k, v in row.items() if k != "details"} for row in rows[offset:offset + limit]],
                "total": len(rows), "offset": offset, "limit": limit}

    def detail(self, handle: str) -> dict | None:
        if not isinstance(handle, str):
            raise ExplorerError("Invalid record handle.")
        value = self._detail.get(handle)
        return json.loads(json.dumps(value)) if value is not None else None
