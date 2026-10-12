"""Strict, explicit-path memory store and reviewed proposal publication."""
from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import uuid
from copy import deepcopy
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import _sign
import _revoke
from _store import secure_replace_bytes


class ConsumerError(ValueError):
    """A store boundary or publication precondition failed."""


SCHEMA = "nockbrain-customer/v1"
PROPOSAL_SCHEMA = "nockbrain-customer-proposal/v1"
LIFECYCLE_SCHEMA = "nockbrain-customer-lifecycle/v1"
JOURNAL_SCHEMA = "nockbrain-customer-journal/v1"
JOURNAL_NAME = ".customer-journal.json"
FACT_LIMIT = 32 * 1024 * 1024
MAX_PROPOSALS = 100
MAX_PROPOSAL_BYTES = 64 * 1024 * 1024
CAPTURE_ORIGIN = "capture"
# Earlier capture digests one capture proposal remembers replacing, oldest
# first. Bounded so a long session cannot grow the proposal per reply; a digest
# older than this window gets the plain missing-proposal error.
MAX_REPLACED = 100
_IMPORT_FIELDS = frozenset({"schema", "store_id", "key_id", "generation",
                            "candidates", "sources", "stats"})
_CAPTURE_FIELDS = _IMPORT_FIELDS | {"origin", "replaces", "transcript_id"}
MAX_TRANSACTION_TEMPS = 100
MAX_TRANSACTION_TEMP_BYTES = 6 * FACT_LIMIT
_ROOT_TEMP = re.compile(r"(?:\.customer-journal-[a-z0-9_]{8}|(?:facts\.json|revocations\.jsonl)\.[a-z0-9_]{8}\.tmp)\Z")
_PROPOSAL_TEMP = re.compile(r"\.proposal-[a-z0-9_]{8}\Z")
SMALL_LIMIT = 16 * 1024
SOURCE_LIMIT = 8 * 1024 * 1024
MAX_SOURCES = 16
MAX_CANDIDATES = 1000
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_HEX128 = re.compile(r"[0-9a-f]{128}\Z")
_CANDIDATE_FIELDS = frozenset({
    "id", "kind", "content", "confidence", "scope", "status", "source",
    "source_file", "source_date", "created_at", "subject", "evidence",
})
_EVIDENCE_FIELDS = frozenset({"store_id", "key_id", "sha256", "path", "line", "event_id"})
_ATTESTATION_FIELDS = frozenset({
    "fact_id", "canonical_fact_hash", "source_hash", "alg", "key_id",
    "signature", "parent_fact_ids", "signed_at",
})


def canonical_bytes(value: Any) -> bytes:
    """Canonical ASCII JSON, rejecting nonfinite numbers and unsupported shapes."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConsumerError("invalid JSON value") from exc


def _json(data: bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ConsumerError("duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(_value):
        raise ConsumerError("nonfinite JSON number")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ConsumerError("nonfinite JSON number")
        return number

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=nonfinite, parse_float=finite_float)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ConsumerError("invalid JSON file") from exc


def _absolute(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise ConsumerError("store path must be absolute")
    return path


def _safe_dir(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ConsumerError("required directory is missing") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or
            info.st_uid != os.getuid()):
        raise ConsumerError("unsafe store directory")


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink, info.st_uid)


def read_regular(path: Path, limit: int) -> bytes:
    """Read one regular file without following its final symlink or accepting drift."""
    path = Path(path)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise ConsumerError("invalid read limit")
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ConsumerError("unsafe regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or _fingerprint(opened) != _fingerprint(before):
                raise ConsumerError("file changed during read")
            if opened.st_size > limit:
                raise ConsumerError("file exceeds size limit")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                data = handle.read(limit + 1)
            after = os.fstat(fd)
            current = path.lstat()
            if (len(data) > limit or len(data) != opened.st_size or
                    _fingerprint(after) != _fingerprint(opened) or
                    _fingerprint(current) != _fingerprint(opened)):
                raise ConsumerError("file changed during read")
            return data
        finally:
            os.close(fd)
    except ConsumerError:
        raise
    except OSError as exc:
        raise ConsumerError("cannot read regular file") from exc


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _sync_file_and_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync_dir(path.parent)


def _write_new_atomic(path: Path, data: bytes, prefix: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink() or path.exists():
            raise ConsumerError("store publication destination exists")
        os.replace(temporary, path)
        temporary = None
        _sync_dir(path.parent)
    finally:
        if temporary is not None:
            os.unlink(temporary)


def _read_owned(path: Path, limit: int, *, allow_paired_link: bool = False) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ConsumerError("required store file is missing") from exc
    if (not stat.S_ISREG(info.st_mode) or
            info.st_nlink not in ({1, 2} if allow_paired_link else {1}) or
            info.st_mode & 0o077 or info.st_uid != os.getuid()):
        raise ConsumerError("unsafe store file")
    data = read_regular(path, limit)
    if _fingerprint(path.lstat()) != _fingerprint(info):
        raise ConsumerError("store file changed during read")
    return data


def _uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def init_store(path: Path) -> dict:
    path = _absolute(path)
    if not path.parent.is_dir():
        raise ConsumerError("store parent must exist")
    try:
        os.mkdir(path, 0o700)
    except OSError as exc:
        raise ConsumerError("store destination already exists or cannot be created") from exc
    # An interrupted initialization stays private and incomplete; it is never adopted.
    try:
        _write_new(path / "facts.json", b"[]\n")
        _write_new(path / ".gitignore", b"*\n")
        os.mkdir(path / "proposals", 0o700)
        key = _sign.load_or_create_key(path / "signing-key", path / "signing-key.pub")
        manifest = {
            "schema": SCHEMA,
            "store_id": str(uuid.uuid4()),
            "key_id": key.key_id,
            "algorithm": key.alg,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_new(path / "customer.json", canonical_bytes(manifest) + b"\n")
        return manifest
    except Exception as exc:
        raise ConsumerError("store initialization incomplete") from exc


def _text(value: Any, max_len: int = 1500) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= max_len and
            bool(value.strip()) and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value))


def _content(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip() or len(value) > 1500:
        return False
    try:
        value.encode("utf-8", errors="strict")
        return True
    except UnicodeError:
        return False


def _safe_path(value: Any) -> bool:
    if not _text(value, 1024):
        return False
    parts = value.split("/")
    if value.startswith("/"):
        parts = parts[1:]
    return (bool(parts) and not any(part in {"", ".", ".."} for part in parts) and
            "\\" not in value)


def _date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _timestamp(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 64:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo is not None
    except ValueError:
        return False


def _captured_keys(private_bytes: bytes, public_bytes: bytes, manifest: dict):
    """Construct both key views from bounded, no-follow captured bytes only."""
    private = _json(private_bytes)
    public = _json(public_bytes)
    algorithm = manifest["algorithm"]
    key_id = manifest["key_id"]
    if algorithm == _sign.ALG_ED25519:
        private_fields = {"alg", "key_id", "private_key"}
        public_fields = {"alg", "key_id", "public_key"}
        material_fields = ((private, "private_key"), (public, "public_key"))
    else:
        private_fields = public_fields = {"alg", "key_id", "secret"}
        material_fields = ((private, "secret"), (public, "secret"))
    if (not isinstance(private, dict) or not isinstance(public, dict) or
            set(private) != private_fields or set(public) != public_fields or
            not isinstance(key_id, str) or
            not re.fullmatch(re.escape(algorithm) + r":[0-9a-f]{16}", key_id) or
            private["alg"] != algorithm or public["alg"] != algorithm or
            private["key_id"] != key_id or public["key_id"] != key_id or
            any(not isinstance(doc[field], str) or
                not _DIGEST.fullmatch(doc[field]) for doc, field in material_fields)):
        raise ConsumerError("invalid store signing keys")
    if algorithm == _sign.ALG_ED25519 and not _sign._HAVE_CRYPTOGRAPHY:
        raise ConsumerError("Ed25519 store key requires cryptography")
    signing_key = _sign._load_key_from_doc(private)
    if algorithm == _sign.ALG_ED25519:
        verifier = _sign.SigningKey(
            _sign.ALG_ED25519,
            ed_public=_sign.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public["public_key"])))
    else:
        verifier = _sign.SigningKey(_sign.ALG_HMAC,
                                    hmac_secret=bytes.fromhex(public["secret"]))
    challenge = b"nockbrain-customer-key-match"
    if (signing_key.key_id != key_id or verifier.key_id != key_id or
            not verifier.verify_bytes(challenge, signing_key.sign_bytes(challenge))):
        raise ConsumerError("store signing keys do not match")
    return signing_key


class ConsumerStore:
    """One locked JSON memory store; all paths are explicit and local."""

    def __init__(self, path: Path):
        self._path = _absolute(path)
        self._manifest: dict = {}
        self._facts: list[dict] = []
        self._generation = ""
        self._lock_fd: int | None = None
        self._key = None
        self._captured: dict[str, bytes | None] = {}
        self._events: list[dict] = []
        self._recovery_required = False

    @property
    def path(self) -> Path:
        return self._path

    @property
    def manifest(self) -> dict:
        """A copy of the verified store identity for callers to inspect."""
        return deepcopy(self._manifest)

    @property
    def facts(self) -> list[dict]:
        """A copy of the verified authoritative records for callers to inspect."""
        if self._recovery_required:
            raise ConsumerError("store recovery required before reading facts")
        return deepcopy(self._facts)

    @property
    def generation(self) -> str:
        return self._generation

    @property
    def recovery_required(self) -> bool:
        return self._recovery_required

    @property
    def revoked_ids(self) -> set[str]:
        return {event["superseded_id"] for event in self._events}

    def __enter__(self) -> "ConsumerStore":
        _safe_dir(self.path)
        _safe_dir(self.path / "proposals")
        lock = self.path / ".customer.lock"
        try:
            self._lock_fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            info = os.fstat(self._lock_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_mode & 0o077 or info.st_uid != os.getuid() or
                    lock.lstat().st_ino != info.st_ino):
                raise ConsumerError("unsafe store lock")
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            self._load()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, _type, _value, _traceback) -> None:
        if self._lock_fd is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None

    def _capture(self) -> dict[str, bytes | None]:
        _safe_dir(self.path)
        _safe_dir(self.path / "proposals")
        for forbidden in ("store-v2", "brain.db"):
            if (self.path / forbidden).is_symlink() or (self.path / forbidden).exists():
                raise ConsumerError("SQLite store is unsupported")
        result: dict[str, bytes | None] = {}
        for name, limit in (("customer.json", SMALL_LIMIT), ("signing-key", SMALL_LIMIT),
                            ("signing-key.pub", SMALL_LIMIT), ("facts.json", FACT_LIMIT)):
            result[name] = _read_owned(self.path / name, limit)
        for name in ("revocations.jsonl", "purged-ids.jsonl"):
            target = self.path / name
            if target.is_symlink() or target.exists():
                data = _read_owned(target, FACT_LIMIT)
                if name == "purged-ids.jsonl" and data.strip():
                    raise ConsumerError("store lifecycle sidecar is nonempty")
                result[name] = data
            else:
                result[name] = None
        return result

    def _load(self) -> None:
        self._captured = self._capture()
        manifest = _json(self._captured["customer.json"])
        if (not isinstance(manifest, dict) or set(manifest) !=
                {"schema", "store_id", "key_id", "algorithm", "created_at"} or
                manifest["schema"] != SCHEMA or not _uuid(manifest["store_id"]) or
                not _text(manifest["key_id"], 128) or
                not isinstance(manifest["algorithm"], str) or
                manifest["algorithm"] not in {_sign.ALG_ED25519, _sign.ALG_HMAC} or
                not _timestamp(manifest["created_at"])):
            raise ConsumerError("invalid store manifest")
        self._manifest = manifest
        try:
            self._key = _captured_keys(self._captured["signing-key"],
                                       self._captured["signing-key.pub"], manifest)
        except ConsumerError:
            raise
        except Exception as exc:
            raise ConsumerError("invalid store signing keys") from exc
        facts = _json(self._captured["facts.json"])
        if not isinstance(facts, list):
            raise ConsumerError("facts must be an array")
        self._validate_facts(facts, require_attestation=True)
        self._facts = facts
        self._events = self._parse_events(self._captured["revocations.jsonl"] or b"")
        temporaries = self._transaction_temps()
        journal_present = self._journal_path().is_symlink() or self._journal_path().exists()
        self._recovery_required = journal_present or bool(temporaries)
        if journal_present:
            self._read_journal()
        else:
            self._validate_lifecycle(facts, self._events)
        if self._capture() != self._captured:
            raise ConsumerError("store changed during opening")
        self._generation = self._generation_for(self._captured)

    @staticmethod
    def _generation_for(captured: dict) -> str:
        return hashlib.sha256(canonical_bytes([
            hashlib.sha256(captured["facts.json"]).hexdigest(),
            hashlib.sha256(captured["revocations.jsonl"] or b"").hexdigest(),
        ])).hexdigest()

    def _validate_facts(self, facts: list, *, require_attestation: bool) -> None:
        if not isinstance(facts, list):
            raise ConsumerError("facts must be an array")
        seen = set()
        for fact in facts:
            self._validate_candidate(fact, signed=require_attestation)
            if fact["id"] in seen:
                raise ConsumerError("duplicate fact ID")
            seen.add(fact["id"])
        if require_attestation:
            result = _sign.verify_facts(facts, self._key)
            if result["valid"] != len(facts):
                raise ConsumerError("fact signature invalid")

    def _validate_candidate(self, fact: Any, *, signed: bool = False) -> None:
        fields = _CANDIDATE_FIELDS | ({"attestation"} if signed else set())
        if signed and isinstance(fact, dict) and fact.get("status") == "superseded":
            fields |= {"superseded_by", "supersession_reason", "superseded_at"}
        if not isinstance(fact, dict) or set(fact) != fields:
            raise ConsumerError("invalid fact fields")
        if (not _text(fact["kind"], 64) or not _content(fact["content"]) or
                not _text(fact["subject"], 256) or not _safe_path(fact["source_file"]) or
                not _date(fact["source_date"]) or not _timestamp(fact["created_at"]) or
                fact["scope"] != "global" or fact["status"] not in ({"current", "superseded"} if signed else {"current"}) or
                fact["source"] != "customer:" + self._manifest["store_id"] or
                isinstance(fact["confidence"], bool) or
                not isinstance(fact["confidence"], (int, float)) or
                not 0 <= fact["confidence"] <= 1 or
                not math.isfinite(fact["confidence"])):
            raise ConsumerError("invalid fact value")
        if signed and fact["status"] == "superseded" and (
                not isinstance(fact["superseded_by"], str) or
                (fact["superseded_by"] and not re.fullmatch(r"customer-[0-9a-f]{64}", fact["superseded_by"])) or
                fact["supersession_reason"] not in {"customer-correction", "customer-forget"} or
                not _timestamp(fact["superseded_at"])):
            raise ConsumerError("invalid supersession")
        expected_id = "customer-" + hashlib.sha256(canonical_bytes([
            self._manifest["store_id"], fact["kind"], fact["content"]])).hexdigest()
        if fact["id"] != expected_id:
            raise ConsumerError("fact ID mismatch")
        evidence = fact["evidence"]
        if not isinstance(evidence, list) or not evidence or len(evidence) > 1000:
            raise ConsumerError("invalid fact evidence")
        for entry in evidence:
            if (not isinstance(entry, dict) or set(entry) != _EVIDENCE_FIELDS or
                    entry["store_id"] != self._manifest["store_id"] or
                    entry["key_id"] != self._manifest["key_id"] or
                    not isinstance(entry["sha256"], str) or not _DIGEST.fullmatch(entry["sha256"]) or
                    not _safe_path(entry["path"]) or
                    not isinstance(entry["line"], int) or isinstance(entry["line"], bool) or
                    entry["line"] < 1 or not _text(entry["event_id"], 256)):
                raise ConsumerError("invalid fact evidence")
        if signed:
            att = fact["attestation"]
            signature_pattern = (_HEX128 if self._manifest["algorithm"] == _sign.ALG_ED25519
                                 else _DIGEST)
            if (not isinstance(att, dict) or set(att) != _ATTESTATION_FIELDS or
                    att["fact_id"] != fact["id"] or
                    not isinstance(att["canonical_fact_hash"], str) or
                    not _DIGEST.fullmatch(att["canonical_fact_hash"]) or
                    not isinstance(att["source_hash"], str) or
                    not _DIGEST.fullmatch(att["source_hash"]) or
                    att["key_id"] != self._manifest["key_id"] or
                    att["alg"] != self._manifest["algorithm"] or
                    not isinstance(att["signature"], str) or
                    not signature_pattern.fullmatch(att["signature"]) or
                    att["parent_fact_ids"] != [] or
                    not _timestamp(att["signed_at"])):
                raise ConsumerError("invalid fact attestation")

    def _parse_events(self, data: bytes, *, check_chain: bool = True) -> list[dict]:
        if data and not data.endswith(b"\n"):
            raise ConsumerError("invalid revocation stream")
        if check_chain:
            # Shared chained-log contract (_revoke): a garbled, missing or
            # reordered line is a refusal, not a skip. A journal event is
            # checked in isolation (check_chain=False) and chained when the
            # whole stream is reloaded.
            chain = _revoke.parse_revocation_log(data)[1]
            if any(chain[field] for field in _revoke.BLOCK_CHAIN):
                raise ConsumerError("invalid revocation stream")
        events = []
        for line in data.splitlines():
            event = _json(line)
            fields = {"schema", "superseded_id", "superseding_id", "reason",
                      "superseded_at", "alg", "key_id", "signature", "signed_at"}
            chained = isinstance(event, dict) and "seq" in event
            if chained:
                fields |= {"seq", "prev_digest"}
            pattern = _HEX128 if self._manifest["algorithm"] == _sign.ALG_ED25519 else _DIGEST
            if (not isinstance(event, dict) or set(event) != fields or
                    (chained and (isinstance(event["seq"], bool) or not isinstance(event["seq"], int) or
                                  event["seq"] < 1 or not isinstance(event["prev_digest"], str) or
                                  not _DIGEST.fullmatch(event["prev_digest"]))) or
                    canonical_bytes(event) != line or event["schema"] != _revoke.SCHEMA or
                    not isinstance(event["superseded_id"], str) or
                    not re.fullmatch(r"customer-[0-9a-f]{64}", event["superseded_id"]) or
                    not isinstance(event["superseding_id"], str) or
                    (event["superseding_id"] and not re.fullmatch(r"customer-[0-9a-f]{64}", event["superseding_id"])) or
                    event["reason"] not in {"customer-correction", "customer-forget"} or
                    (event["reason"] == "customer-forget" and event["superseding_id"]) or
                    (event["reason"] == "customer-correction" and not event["superseding_id"]) or
                    not _timestamp(event["superseded_at"]) or
                    not _timestamp(event["signed_at"]) or
                    event["alg"] != self._manifest["algorithm"] or
                    event["key_id"] != self._manifest["key_id"] or
                    not isinstance(event["signature"], str) or
                    not pattern.fullmatch(event["signature"]) or
                    not _revoke.verify_revocation(event, self._key)):
                raise ConsumerError("invalid revocation event")
            events.append(event)
        return events

    def _validate_lifecycle(self, facts: list[dict], events: list[dict]) -> None:
        by_id = {fact["id"]: fact for fact in facts}
        revoked = {event["superseded_id"] for event in events}
        forgotten = {event["superseded_id"] for event in events
                     if event["reason"] == "customer-forget"}
        attestations = {(event["superseded_id"], event["superseding_id"],
                         event["reason"], event["superseded_at"]) for event in events}
        for fact in facts:
            if fact["id"] in forgotten:
                raise ConsumerError("forgotten fact was restored")
            if fact["id"] in revoked and fact["status"] != "superseded":
                raise ConsumerError("revoked fact is current")
            if fact["status"] == "superseded" and (
                    fact["id"], fact["superseded_by"],
                    fact["supersession_reason"], fact["superseded_at"]) not in attestations:
                raise ConsumerError("unattested supersession")
        for event in events:
            if (event["reason"] == "customer-correction" and
                    event["superseding_id"] not in by_id and
                    event["superseding_id"] not in revoked):
                raise ConsumerError("replacement fact is missing")

    def _journal_path(self) -> Path:
        return self.path / JOURNAL_NAME

    def _transaction_temps(self) -> list[Path]:
        """Inventory only temporary names produced by store publication helpers."""
        paths = []
        total = 0
        for directory, pattern in ((self.path, _ROOT_TEMP),
                                   (self.path / "proposals", _PROPOSAL_TEMP)):
            for path in directory.iterdir():
                if not pattern.fullmatch(path.name):
                    continue
                info = path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                        info.st_mode & 0o077 or info.st_nlink not in {1, 2}):
                    raise ConsumerError("unsafe transaction temporary file")
                if info.st_nlink == 2:
                    if directory == self.path and path.name.startswith(".customer-journal-"):
                        partners = [self._journal_path()]
                    elif directory == self.path / "proposals":
                        partners = [p for p in directory.iterdir()
                                    if re.fullmatch(r"[0-9a-f]{64}\.json", p.name)]
                    else:
                        raise ConsumerError("unsafe transaction temporary link")
                    if not any(self._same_owned_inode(path, partner) for partner in partners):
                        raise ConsumerError("unpaired transaction temporary link")
                paths.append(path)
                total += info.st_size
                if len(paths) > MAX_TRANSACTION_TEMPS or total > MAX_TRANSACTION_TEMP_BYTES:
                    raise ConsumerError("transaction temporary limit exceeded")
        return paths

    @staticmethod
    def _same_owned_inode(first: Path, second: Path) -> bool:
        try:
            a, b = first.lstat(), second.lstat()
        except OSError:
            return False
        return (stat.S_ISREG(b.st_mode) and b.st_uid == os.getuid() and
                not b.st_mode & 0o077 and b.st_nlink == 2 and
                (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino))

    def _cleanup_temps(self) -> bool:
        paths = self._transaction_temps()
        for path in paths:
            path.unlink()
        if paths:
            _sync_dir(self.path)
            _sync_dir(self.path / "proposals")
        return bool(paths)

    def _read_journal(self) -> dict:
        journal_path = self._journal_path()
        info = journal_path.lstat()
        if info.st_nlink == 2 and not any(
                self._same_owned_inode(path, journal_path) for path in self._transaction_temps()
                if path.parent == self.path and path.name.startswith(".customer-journal-")):
            raise ConsumerError("unpaired recovery journal")
        data = _read_owned(journal_path, MAX_PROPOSAL_BYTES, allow_paired_link=True)
        journal = _json(data)
        fields = {"schema", "store_id", "key_id", "action", "fact_id", "before_facts",
                  "before_revocations", "after_facts", "event", "signature"}
        if not isinstance(journal, dict) or set(journal) != fields:
            raise ConsumerError("invalid recovery journal")
        signature = journal.pop("signature")
        try:
            valid = (journal["schema"] == JOURNAL_SCHEMA and
                     journal["store_id"] == self._manifest["store_id"] and
                     journal["key_id"] == self._manifest["key_id"] and
                     journal["action"] in {"correct", "forget"} and
                     isinstance(journal["fact_id"], str) and
                     re.fullmatch(r"customer-[0-9a-f]{64}", journal["fact_id"]) and
                     all(isinstance(journal[k], str) and _DIGEST.fullmatch(journal[k])
                         for k in ("before_facts", "before_revocations")) and
                     isinstance(signature, str) and
                     self._key.verify_bytes(b"nockbrain-customer-journal-v1\n" + canonical_bytes(journal), signature))
        except (TypeError, ValueError, KeyError):
            valid = False
        journal["signature"] = signature
        if not valid:
            raise ConsumerError("invalid recovery journal")
        after = journal["after_facts"]
        self._validate_facts(after, require_attestation=True)
        event = journal["event"]
        self._parse_events(canonical_bytes(event) + b"\n", check_chain=False)
        if event["superseded_id"] != journal["fact_id"] or event["reason"] != "customer-" + (
                "correction" if journal["action"] == "correct" else "forget"):
            raise ConsumerError("invalid recovery journal")
        before_facts = self._captured["facts.json"]
        after_bytes = canonical_bytes(after) + b"\n"
        if hashlib.sha256(before_facts).hexdigest() not in {
                journal["before_facts"], hashlib.sha256(after_bytes).hexdigest()}:
            raise ConsumerError("recovery facts changed")
        prior_rev = self._captured["revocations.jsonl"] or b""
        event_bytes = canonical_bytes(event) + b"\n"
        if hashlib.sha256(prior_rev).hexdigest() != journal["before_revocations"]:
            if (not prior_rev.endswith(event_bytes) or
                    hashlib.sha256(prior_rev[:-len(event_bytes)]).hexdigest() != journal["before_revocations"]):
                raise ConsumerError("recovery revocations changed")
        if hashlib.sha256(before_facts).hexdigest() == journal["before_facts"]:
            self._check_transition(self._facts, after, event, journal["action"])
        else:
            if self._facts != after:
                raise ConsumerError("recovery facts changed")
        return journal

    def _check_transition(self, before: list[dict], after: list[dict], event: dict, action: str) -> None:
        selected = next((f for f in before if f["id"] == event["superseded_id"]), None)
        if selected is None:
            raise ConsumerError("recovery target missing")
        if action == "forget":
            expected = [f for f in before if f["id"] != selected["id"]]
        else:
            if selected["status"] != "current" or len(after) != len(before) + 1:
                raise ConsumerError("invalid correction transition")
            expected = deepcopy(before)
            old = next(f for f in expected if f["id"] == selected["id"])
            old.update(status="superseded", superseded_by=event["superseding_id"],
                       supersession_reason=event["reason"], superseded_at=event["superseded_at"])
            replacement = after[-1]
            if replacement["id"] != event["superseding_id"] or replacement["status"] != "current":
                raise ConsumerError("invalid replacement fact")
            expected.append(replacement)
        if expected != after:
            raise ConsumerError("invalid lifecycle transition")

    @staticmethod
    def _check_receipts(candidates: list, sources: list) -> None:
        anchors = {(source["path"], source["sha256"]) for source in sources}
        for fact in candidates:
            if fact["source_file"] != Path(fact["evidence"][0]["path"]).name:
                raise ConsumerError("candidate source filename mismatch")
            for evidence in fact["evidence"]:
                if (evidence["path"], evidence["sha256"]) not in anchors:
                    raise ConsumerError("candidate evidence has no source receipt")

    def _validate_proposal_inputs(self, candidates: Any, sources: Any, stats: Any) -> None:
        if not isinstance(candidates, list) or len(candidates) > MAX_CANDIDATES:
            raise ConsumerError("too many candidates")
        self._validate_facts(candidates, require_attestation=False)
        if not isinstance(sources, list) or len(sources) > MAX_SOURCES:
            raise ConsumerError("too many source receipts")
        for source in sources:
            if (not isinstance(source, dict) or set(source) != {"path", "sha256", "format"} or
                    not _safe_path(source["path"]) or not isinstance(source["sha256"], str) or
                    not _DIGEST.fullmatch(source["sha256"]) or
                    not isinstance(source["format"], str) or
                    source["format"] not in {"markdown", "claude-jsonl"}):
                raise ConsumerError("invalid source receipt")
        self._check_receipts(candidates, sources)
        if (not isinstance(stats, dict) or not {"files", "candidates", "overlong_skipped"} <= set(stats) or
                any(not isinstance(k, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", k) or
                    not isinstance(v, int) or isinstance(v, bool) or v < 0 for k, v in stats.items()) or
                stats["files"] != len(sources) or stats["candidates"] != len(candidates)):
            raise ConsumerError("invalid proposal statistics")

    def save_proposal(self, candidates: list, sources: list, stats: dict) -> str:
        self._ready()
        self._validate_proposal_inputs(candidates, sources, stats)
        proposal = {"schema": PROPOSAL_SCHEMA, "store_id": self._manifest["store_id"],
                    "key_id": self._manifest["key_id"], "generation": self._generation,
                    "candidates": candidates, "sources": sources, "stats": stats}
        data = canonical_bytes(proposal)
        if len(data) > FACT_LIMIT:
            raise ConsumerError("proposal exceeds size limit")
        digest = hashlib.sha256(data).hexdigest()
        destination = self.path / "proposals" / (digest + ".json")
        if destination.exists() or destination.is_symlink():
            if self._read_proposal_bytes(destination) != data:
                raise ConsumerError("proposal changed")
            return digest
        self._check_queue(len(data))
        self._publish_proposal(destination, data)
        return digest

    def _publish_proposal(self, destination: Path, data: bytes) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".proposal-", dir=self.path / "proposals")
        try:
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if destination.is_symlink() or destination.exists():
                if self._read_proposal_bytes(destination) != data:
                    raise ConsumerError("proposal changed")
            else:
                os.replace(temporary, destination)
                temporary = None
                _sync_dir(destination.parent)
        finally:
            if temporary is not None:
                os.unlink(temporary)

    def _read_proposal_bytes(self, path: Path) -> bytes:
        try:
            info = path.lstat()
        except OSError as exc:
            raise ConsumerError("required proposal is missing") from exc
        if info.st_nlink == 2 and not any(
                self._same_owned_inode(temp, path) for temp in self._transaction_temps()
                if temp.parent == self.path / "proposals"):
            raise ConsumerError("unsafe unpaired proposal")
        return _read_owned(path, FACT_LIMIT, allow_paired_link=True)

    def read_proposal(self, digest: str) -> dict:
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ConsumerError("proposal digest must be full SHA-256")
        path = self.path / "proposals" / (digest + ".json")
        proposal = None
        if path.exists() or path.is_symlink():
            proposal = self._load_proposal(digest)
            if proposal.get("origin") != CAPTURE_ORIGIN:
                return proposal
        newer = self._newer_capture(digest)
        if newer is not None:
            raise ConsumerError("proposal was replaced by a newer capture of the same "
                                "transcript (" + newer + "); run pending")
        if proposal is None:
            raise ConsumerError("required proposal is missing")
        return proposal

    def _load_proposal(self, digest: str, *, capture_only: bool = False) -> dict | None:
        """Read and validate one saved proposal, without the replacement check.

        With ``capture_only``, anything that does not declare itself a capture
        proposal returns None before the costly candidate and signature checks.
        """
        data = self._read_proposal_bytes(self.path / "proposals" / (digest + ".json"))
        if hashlib.sha256(data).hexdigest() != digest:
            raise ConsumerError("proposal digest changed")
        proposal = _json(data)
        if not isinstance(proposal, dict):
            raise ConsumerError("invalid proposal envelope")
        if capture_only and (proposal.get("schema") != PROPOSAL_SCHEMA or
                             proposal.get("origin") != CAPTURE_ORIGIN):
            return None
        if proposal.get("schema") == LIFECYCLE_SCHEMA:
            fields = {"schema", "store_id", "key_id", "generation", "action", "fact_id",
                      "replacement", "replacement_proposal", "signature"}
            if set(proposal) != fields or proposal["action"] not in {"correct", "forget"} or (
                    proposal["action"] == "forget" and (proposal["replacement"] is not None or
                                                          proposal["replacement_proposal"] is not None)) or (
                    proposal["action"] == "correct" and not isinstance(proposal["replacement"], dict)):
                raise ConsumerError("invalid lifecycle proposal")
            if proposal["replacement"] is not None:
                self._validate_candidate(proposal["replacement"])
                source_digest = proposal["replacement_proposal"]
                if not isinstance(source_digest, str) or not _DIGEST.fullmatch(source_digest):
                    raise ConsumerError("invalid replacement proposal")
            unsigned = {key: value for key, value in proposal.items() if key != "signature"}
            signature = proposal["signature"]
            pattern = _HEX128 if self._manifest["algorithm"] == _sign.ALG_ED25519 else _DIGEST
            if (not isinstance(signature, str) or not pattern.fullmatch(signature) or
                    not self._key.verify_bytes(b"nockbrain-customer-lifecycle-v1\n" +
                                               canonical_bytes(unsigned), signature)):
                raise ConsumerError("invalid lifecycle proposal signature")
            if not isinstance(proposal["fact_id"], str) or not re.fullmatch(r"customer-[0-9a-f]{64}", proposal["fact_id"]):
                raise ConsumerError("invalid lifecycle target")
        elif (proposal.get("schema") != PROPOSAL_SCHEMA or
                set(proposal) not in (_IMPORT_FIELDS, _CAPTURE_FIELDS)):
            raise ConsumerError("invalid proposal envelope")
        if (
                proposal["store_id"] != self._manifest["store_id"] or
                proposal["key_id"] != self._manifest["key_id"] or
                not isinstance(proposal["generation"], str) or
                not _DIGEST.fullmatch(proposal["generation"])):
            raise ConsumerError("invalid proposal envelope")
        if proposal["schema"] == PROPOSAL_SCHEMA:
            self._validate_proposal_inputs(proposal["candidates"], proposal["sources"], proposal["stats"])
            if "origin" in proposal:
                replaces = proposal["replaces"]
                if (proposal["origin"] != CAPTURE_ORIGIN or not isinstance(replaces, list) or
                        len(replaces) > MAX_REPLACED or
                        any(not isinstance(item, str) or not _DIGEST.fullmatch(item)
                            for item in replaces) or
                        len(set(replaces)) != len(replaces) or digest in replaces or
                        not isinstance(proposal["transcript_id"], str) or
                        not _DIGEST.fullmatch(proposal["transcript_id"]) or
                        len(proposal["sources"]) != 1 or
                        proposal["sources"][0]["format"] != "claude-jsonl"):
                    raise ConsumerError("invalid capture proposal")
        return proposal

    @staticmethod
    def _capture_key(proposal: dict) -> tuple[str, str, str]:
        source = proposal["sources"][0]
        return source["path"], source["format"], proposal["transcript_id"]

    def _transcript_id(self, transcript: Any) -> str:
        """Store-scoped hash of the resolved transcript path.

        The receipt path alone is not a safe key: the secret scrubber can
        rewrite two different paths (for example 32-hex file names) to the
        same text. The hash adds no path text to the proposal.
        """
        if (not isinstance(transcript, str) or not transcript.startswith("/") or
                len(transcript) > 2048):
            raise ConsumerError("capture requires an absolute transcript path")
        return hashlib.sha256(canonical_bytes([
            "nockbrain-capture-transcript/v1", self._manifest["store_id"], transcript,
        ])).hexdigest()

    def _remove_proposals(self, digests) -> None:
        proposals = self.path / "proposals"
        for digest in sorted(digests):
            try:
                (proposals / (digest + ".json")).unlink()
            except FileNotFoundError:
                pass
        if digests:
            _sync_dir(proposals)

    def _capture_proposals(self) -> dict[str, dict]:
        """Every readable capture proposal in the queue, by digest.

        An entry that fails validation is skipped, never matched: it cannot be
        shown to be a capture of any transcript, so capture never removes it
        and it still surfaces through pending and review.
        """
        captures = {}
        for digest, _size in self._queue_entries():
            try:
                proposal = self._load_proposal(digest, capture_only=True)
            except ConsumerError:
                continue
            if proposal is not None:
                captures[digest] = proposal
        return captures

    @classmethod
    def _replaced_captures(cls, captures: dict[str, dict]) -> dict[str, str]:
        """Saved capture digests already replaced, mapped to a replacing digest.

        Only a capture proposal of the same transcript (receipt path, format
        and transcript ID) can replace one, so neither ``propose`` nor lifecycle proposals
        can be hidden or removed through a ``replaces`` list.
        """
        replaced = {}
        for digest, proposal in sorted(captures.items()):
            for old in proposal["replaces"]:
                if old in captures and cls._capture_key(captures[old]) == cls._capture_key(proposal):
                    replaced[old] = digest
        return replaced

    def _newer_capture(self, digest: str) -> str | None:
        """The current capture proposal that replaced ``digest``, if any."""
        captures = self._capture_proposals()
        replaced = self._replaced_captures(captures)
        if digest in captures:
            newer = replaced.get(digest)
        else:
            newer = next((other for other, proposal in sorted(captures.items())
                          if digest in proposal["replaces"]), None)
        seen = set()
        while newer in replaced and newer not in seen:
            seen.add(newer)
            newer = replaced[newer]
        return newer

    def save_capture(self, candidates: list, sources: list, stats: dict,
                     transcript: str) -> dict:
        """Save the single current capture proposal for one transcript.

        The new proposal records ``origin: capture``, a ``transcript_id`` (see
        ``_transcript_id``) and, in ``replaces``, every earlier capture digest
        of the same transcript (receipt path, format and transcript ID).
        Publishing it is the commit point: from then on the earlier digests
        are replaced, whether or not their files are gone yet. Their files are
        removed under the same lock right after; a process death in between
        leaves files that pending hides, review and apply refuse, and the next
        capture removes before anything else. Nothing is lost, because capture
        re-reads the whole transcript and the new proposal carries every
        candidate not yet stored or revoked. Proposals from ``propose`` (no
        origin), lifecycle proposals and other transcripts are never touched.
        Returns the digest and how many pending proposals it replaced; an
        unchanged transcript returns the current digest and saves nothing new.
        """
        self._ready()
        self._validate_proposal_inputs(candidates, sources, stats)
        if len(sources) != 1 or sources[0]["format"] != "claude-jsonl":
            raise ConsumerError("capture requires one transcript receipt")
        transcript_id = self._transcript_id(transcript)
        key = self._capture_key({"sources": sources, "transcript_id": transcript_id})
        captures = self._capture_proposals()
        # Leftovers of an interrupted capture are already replaced by a
        # published proposal; removing them first keeps them out of the queue
        # limit below, even when this transcript has not changed.
        leftovers = self._replaced_captures(captures)
        self._remove_proposals(leftovers)
        earlier = sorted((digest for digest, existing in captures.items()
                          if digest not in leftovers and self._capture_key(existing) == key),
                         key=lambda digest: (len(captures[digest]["replaces"]), digest))
        base = {"schema": PROPOSAL_SCHEMA, "store_id": self._manifest["store_id"],
                "key_id": self._manifest["key_id"], "generation": self._generation,
                "candidates": candidates, "sources": sources, "stats": stats}
        for digest in earlier:
            current = {k: v for k, v in captures[digest].items()
                       if k not in ("origin", "replaces", "transcript_id")}
            if canonical_bytes(current) == canonical_bytes(base):
                return {"digest": digest, "replaced": 0}
        history: list[str] = []
        for digest in earlier:
            for item in captures[digest]["replaces"] + [digest]:
                if item not in history:
                    history.append(item)
        proposal = dict(base, origin=CAPTURE_ORIGIN, replaces=history[-MAX_REPLACED:],
                        transcript_id=transcript_id)
        data = canonical_bytes(proposal)
        if len(data) > FACT_LIMIT:
            raise ConsumerError("proposal exceeds size limit")
        digest = hashlib.sha256(data).hexdigest()
        destination = self.path / "proposals" / (digest + ".json")
        if destination.exists() or destination.is_symlink():
            if self._read_proposal_bytes(destination) != data:
                raise ConsumerError("proposal changed")
        else:
            self._check_queue(len(data))
            self._publish_proposal(destination, data)
        # Commit point passed: removing the earlier files is only cleanup.
        self._remove_proposals(set(earlier) - {digest})
        return {"digest": digest, "replaced": len(earlier)}

    def apply_proposal(self, digest: str) -> dict:
        self._ready()
        proposal = self.read_proposal(digest)
        if proposal["generation"] != self._generation:
            raise ConsumerError("stale proposal")
        if proposal["schema"] == LIFECYCLE_SCHEMA:
            return self._apply_lifecycle(proposal)
        seen = {fact["id"] for fact in self._facts}
        new = []
        skipped = 0
        for candidate in proposal["candidates"]:
            if candidate["id"] in seen or candidate["id"] in self.revoked_ids:
                skipped += 1
            else:
                new.append(dict(candidate))
                seen.add(candidate["id"])
        if new:
            _sign.sign_facts(new, self._key)
        merged = self._facts + new
        self._validate_facts(merged, require_attestation=True)
        if self._capture() != self._captured:
            raise ConsumerError("store changed during publication")
        if new:
            output = canonical_bytes(merged) + b"\n"
            if len(output) > FACT_LIMIT:
                raise ConsumerError("facts exceed size limit")
            try:
                replaced = secure_replace_bytes(
                    self.path / "facts.json", output,
                    before_replace=lambda: self._capture() == self._captured)
                if not replaced:
                    raise ConsumerError("store changed during publication")
            except Exception as exc:
                raise ConsumerError("store publication failed") from exc
            self._facts = merged
            self._captured["facts.json"] = output
            self._generation = self._generation_for(self._captured)
        return {"added": len(new), "skipped": skipped, "total": len(merged)}

    def _ready(self) -> None:
        if self._recovery_required:
            raise ConsumerError("store recovery required")
        if self._capture() != self._captured:
            raise ConsumerError("store changed")

    def _reject_derived(self) -> None:
        for name in ("insights.json", "graph.json", "embeddings.npz", "vault",
                     "sessions", "facts.json.verified-cache.json", "projection-receipts.jsonl"):
            path = self.path / name
            if path.is_symlink() or path.exists():
                raise ConsumerError("derived outputs must be removed before lifecycle change")

    def _queue_entries(self) -> list[tuple[str, int]]:
        entries = []
        total = 0
        count = 0
        temporaries = self._transaction_temps()
        for path in (self.path / "proposals").iterdir():
            is_proposal = bool(re.fullmatch(r"[0-9a-f]{64}\.json", path.name))
            is_temp = bool(_PROPOSAL_TEMP.fullmatch(path.name))
            if not is_proposal and not is_temp:
                raise ConsumerError("unexpected proposal file")
            info = path.lstat()
            paired = (is_proposal and info.st_nlink == 2 and
                      any(self._same_owned_inode(temp, path) for temp in temporaries
                          if temp.parent == self.path / "proposals"))
            if (not stat.S_ISREG(info.st_mode) or
                    (info.st_nlink != 1 and not paired and not (is_temp and info.st_nlink == 2)) or
                    info.st_uid != os.getuid() or info.st_mode & 0o077):
                raise ConsumerError("unsafe proposal file")
            if is_proposal:
                count += 1
                total += info.st_size
                entries.append((path.name[:-5], info.st_size))
            if count > MAX_PROPOSALS or total > MAX_PROPOSAL_BYTES:
                raise ConsumerError("proposal queue exceeds limit")
        return sorted(entries)

    def _check_queue(self, added_bytes: int) -> None:
        self._queue_entries()
        paths = list((self.path / "proposals").iterdir())
        if len(paths) >= MAX_PROPOSALS or sum(path.lstat().st_size for path in paths) + added_bytes > MAX_PROPOSAL_BYTES:
            raise ConsumerError("proposal queue is full")

    def pending_proposals(self) -> list[dict]:
        loaded = [(digest, self._load_proposal(digest)) for digest, _size in self._queue_entries()]
        replaced = self._replaced_captures({digest: proposal for digest, proposal in loaded
                                            if proposal.get("origin") == CAPTURE_ORIGIN})
        pending = []
        for digest, proposal in loaded:
            if digest in replaced:
                continue
            pending.append({"digest": digest,
                            "action": proposal.get("action", "import"),
                            "count": len(proposal["candidates"]) if "candidates" in proposal else (1 if proposal["replacement"] else 0),
                            "stale": proposal["generation"] != self._generation})
        return pending

    def discard_proposal(self, digest: str) -> dict:
        self._ready()
        proposal = self.read_proposal(digest)
        if proposal.get("origin") == CAPTURE_ORIGIN:
            # Remove leftover files this capture replaced first, so discarding
            # the current proposal cannot bring an older copy back.
            captures = self._capture_proposals()
            self._remove_proposals({
                old for old in proposal["replaces"]
                if old in captures and self._capture_key(captures[old]) == self._capture_key(proposal)})
        (self.path / "proposals" / (digest + ".json")).unlink()
        _sync_dir(self.path / "proposals")
        return {"discarded": digest}

    def status(self) -> dict:
        return {"store_id": self._manifest["store_id"],
                "generation": self._generation,
                "facts": len(self._facts),
                "current": sum(f["status"] == "current" for f in self._facts),
                "superseded": sum(f["status"] == "superseded" for f in self._facts),
                "revoked": len(self.revoked_ids),
                "pending": len(self._queue_entries()),
                "recovery_required": self._recovery_required}

    def _save_lifecycle(self, action: str, fact_id: str, replacement: dict | None,
                        replacement_proposal: str | None = None) -> str:
        self._ready()
        if not isinstance(fact_id, str) or not re.fullmatch(r"customer-[0-9a-f]{64}", fact_id):
            raise ConsumerError("invalid fact ID")
        target = next((fact for fact in self._facts if fact["id"] == fact_id), None)
        if target is None:
            raise ConsumerError("fact is missing")
        if action == "correct" and target["status"] != "current":
            raise ConsumerError("only a current fact can be corrected")
        if action == "correct":
            self._validate_candidate(replacement)
            if replacement["id"] == fact_id or replacement["id"] in {f["id"] for f in self._facts} or replacement["id"] in self.revoked_ids:
                raise ConsumerError("replacement must be a new unrevoked fact")
        proposal = {"schema": LIFECYCLE_SCHEMA, "store_id": self._manifest["store_id"],
                    "key_id": self._manifest["key_id"], "generation": self._generation,
                    "action": action, "fact_id": fact_id, "replacement": replacement,
                    "replacement_proposal": replacement_proposal}
        proposal["signature"] = self._key.sign_bytes(
            b"nockbrain-customer-lifecycle-v1\n" + canonical_bytes(proposal))
        data = canonical_bytes(proposal)
        digest = hashlib.sha256(data).hexdigest()
        path = self.path / "proposals" / (digest + ".json")
        if path.exists() or path.is_symlink():
            if self._read_proposal_bytes(path) != data:
                raise ConsumerError("proposal changed")
            return digest
        self._check_queue(len(data))
        self._publish_proposal(path, data)
        return digest

    def propose_correction(self, fact_id: str, replacement_digest: str) -> str:
        source = self.read_proposal(replacement_digest)
        if source["schema"] != PROPOSAL_SCHEMA or source["generation"] != self._generation or len(source["candidates"]) != 1:
            raise ConsumerError("correction requires one current import candidate")
        return self._save_lifecycle("correct", fact_id, source["candidates"][0], replacement_digest)

    def propose_forget(self, fact_id: str) -> str:
        return self._save_lifecycle("forget", fact_id, None)

    def _apply_lifecycle(self, proposal: dict) -> dict:
        self._reject_derived()
        action, fact_id = proposal["action"], proposal["fact_id"]
        old = next((f for f in self._facts if f["id"] == fact_id), None)
        if old is None:
            raise ConsumerError("fact is missing")
        if action == "correct" and old["status"] != "current":
            raise ConsumerError("only a current fact can be corrected")
        replacement = deepcopy(proposal["replacement"])
        if replacement is not None and (replacement["id"] == fact_id or
                replacement["id"] in {f["id"] for f in self._facts} or replacement["id"] in self.revoked_ids):
            raise ConsumerError("replacement must be a new unrevoked fact")
        # Chain position comes from the captured stream under the store
        # lock; the journal then publishes exactly this event at that position.
        seq, prev_digest = _revoke.chain_position(self._captured["revocations.jsonl"] or b"")
        if action == "correct":
            _sign.sign_facts([replacement], self._key)
            after = deepcopy(self._facts)
            target = next(f for f in after if f["id"] == fact_id)
            event = _revoke.sign_revocation(self._key, superseded_id=fact_id,
                                            superseding_id=replacement["id"], reason="customer-correction",
                                            seq=seq, prev_digest=prev_digest)
            target.update(status="superseded", superseded_by=replacement["id"],
                          supersession_reason=event["reason"], superseded_at=event["superseded_at"])
            after.append(replacement)
        else:
            event = _revoke.sign_revocation(self._key, superseded_id=fact_id,
                                            reason="customer-forget",
                                            seq=seq, prev_digest=prev_digest)
            after = [deepcopy(f) for f in self._facts if f["id"] != fact_id]
        self._check_transition(self._facts, after, event, action)
        self._validate_facts(after, require_attestation=True)
        self._validate_lifecycle(after, self._events + [event])
        output = canonical_bytes(after) + b"\n"
        if len(output) > FACT_LIMIT:
            raise ConsumerError("facts exceed size limit")
        journal = {"schema": JOURNAL_SCHEMA, "store_id": self._manifest["store_id"],
                   "key_id": self._manifest["key_id"], "action": action, "fact_id": fact_id,
                   "before_facts": hashlib.sha256(self._captured["facts.json"]).hexdigest(),
                   "before_revocations": hashlib.sha256(self._captured["revocations.jsonl"] or b"").hexdigest(),
                   "after_facts": after, "event": event}
        journal["signature"] = self._key.sign_bytes(
            b"nockbrain-customer-journal-v1\n" + canonical_bytes(journal))
        if len(self._captured["revocations.jsonl"] or b"") + len(canonical_bytes(event)) + 1 > FACT_LIMIT:
            raise ConsumerError("revocation stream exceeds size limit")
        if len(canonical_bytes(journal)) > MAX_PROPOSAL_BYTES:
            raise ConsumerError("recovery journal exceeds size limit")
        self._ready()
        try:
            _write_new_atomic(self._journal_path(), canonical_bytes(journal), ".customer-journal-")
        except OSError as exc:
            raise ConsumerError("journal publication failed") from exc
        finally:
            self._recovery_required = self._journal_path().is_symlink() or self._journal_path().exists()
        self.recover()
        return {"action": action, "fact_id": fact_id,
                "replacement_id": replacement["id"] if replacement else None,
                "total": len(after)}

    def recover(self) -> dict:
        try:
            return self._recover_unchecked()
        except OSError as exc:
            raise ConsumerError("store recovery failed") from exc

    def _recover_unchecked(self) -> dict:
        if not self._recovery_required:
            return {"recovered": False}
        self._load()
        if not self._recovery_required:
            return {"recovered": False}
        if not (self._journal_path().is_symlink() or self._journal_path().exists()):
            self._cleanup_temps()
            self._recovery_required = False
            return {"recovered": True, "action": "cleanup", "total": len(self._facts)}
        self._reject_derived()
        journal = self._read_journal()
        event_bytes = canonical_bytes(journal["event"]) + b"\n"
        before_rev = self._captured["revocations.jsonl"] or b""
        if hashlib.sha256(before_rev).hexdigest() == journal["before_revocations"]:
            output = before_rev + event_bytes
            if len(output) > FACT_LIMIT:
                raise ConsumerError("revocation stream exceeds size limit")
            try:
                if not secure_replace_bytes(self.path / "revocations.jsonl", output,
                                            before_replace=lambda: self._capture() == self._captured):
                    raise ConsumerError("store changed during recovery")
            except Exception as exc:
                raise ConsumerError("recovery publication failed") from exc
            _sync_file_and_dir(self.path / "revocations.jsonl")
            self._captured["revocations.jsonl"] = output
            self._events.append(journal["event"])
        after_bytes = canonical_bytes(journal["after_facts"]) + b"\n"
        if self._captured["facts.json"] != after_bytes:
            try:
                if not secure_replace_bytes(self.path / "facts.json", after_bytes,
                                            before_replace=lambda: self._capture() == self._captured):
                    raise ConsumerError("store changed during recovery")
            except Exception as exc:
                raise ConsumerError("recovery publication failed") from exc
            _sync_file_and_dir(self.path / "facts.json")
            self._captured["facts.json"] = after_bytes
            self._facts = journal["after_facts"]
        self._cleanup_temps()
        if journal["action"] == "forget":
            for digest, _size in self._queue_entries():
                (self.path / "proposals" / (digest + ".json")).unlink()
            _sync_dir(self.path / "proposals")
        self._validate_lifecycle(self._facts, self._events)
        self._journal_path().unlink()
        _sync_dir(self.path)
        self._recovery_required = False
        self._generation = self._generation_for(self._captured)
        return {"recovered": True, "action": journal["action"], "total": len(self._facts)}
