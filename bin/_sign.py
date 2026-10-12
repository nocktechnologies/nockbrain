"""Signed, tamper-evident fact provenance for the NockBrain memory store.

OWASP audit finding F5: any local process can edit ``facts.json`` and poison
what gets injected into an agent's context. There was no cryptographic
integrity. This module adds a signed *fact envelope* so tampering is detectable.

Design:

- Sign each fact's CORE content (``id`` + ``kind`` + ``content``) and its source
  anchor (the evidence pointer) under a deterministic canonicalization (sorted
  keys, no whitespace drift) so signatures are stable across re-serialization.
- Prefer Ed25519 via ``cryptography``; fall back to HMAC-SHA256 (stdlib only)
  when ``cryptography`` is not importable. The import is graceful: installs
  without ``cryptography`` still sign and verify, just with the HMAC algo. The
  algorithm in force is recorded on every attestation via ``alg`` + ``key_id``.
- Derived facts carry ``parent_fact_ids``; the signature covers the fact hash
  PLUS the canonical hashes of those parents (Merkle-style ancestry), so a
  changed or revoked parent makes the child verify as ``parent-suspect``.

The attestation envelope added to each fact::

    "attestation": {
        "fact_id":            <str>,            # the fact's id at sign time
        "canonical_fact_hash":<sha256 hex>,     # over {id, kind, content}
        "source_hash":        <sha256 hex>,     # over the evidence anchor
        "alg":                "ed25519"|"hmac-sha256",
        "key_id":             <str>,            # fingerprint of the signing key
        "signature":          <hex>,            # over the signed payload
        "parent_fact_ids":    [<str>, ...],     # Merkle ancestry (may be empty)
        "signed_at":          <iso8601 utc>,
    }

The private key is NEVER logged and NEVER serialized into facts.json.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# bin/ has no package structure; import sibling helpers by adding bin/ to path.
import sys

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from _store import secure_mkdir, secure_write_text  # noqa: E402

# --- graceful cryptography import -------------------------------------------
# If cryptography is importable we sign with Ed25519; otherwise we fall back to
# HMAC-SHA256 from the stdlib. The fallback is permanent (not removed even when
# cryptography is added to requirements) so the product never hard-depends on it.
try:  # pragma: no cover - exercised via monkeypatch in tests
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - import-failure path
    _HAVE_CRYPTOGRAPHY = False

ALG_ED25519 = "ed25519"
ALG_HMAC = "hmac-sha256"

DEFAULT_STORE_DIR = Path.home() / ".nock-brain"
DEFAULT_KEY_PATH = DEFAULT_STORE_DIR / "signing-key"
DEFAULT_PUB_PATH = DEFAULT_STORE_DIR / "signing-key.pub"

# Domain-separation prefix keeps these signatures from being valid in any other
# context that might reuse the same key bytes.
_DOMAIN = b"nockbrain-fact-v1\n"

CLAIM_ATTESTATION_V2_SCHEMA = "nock-claim-attestation/v2"
CLAIM_ATTESTATION_V2_DOMAIN = b"nock-claim-attestation-v2\n"
VERIFIER_RECEIPT_SCHEMA = "nock-claim-verifier-receipt/v1"
VERIFIER_RECEIPT_DOMAIN = b"nock-claim-verifier-receipt-v1\n"
VERIFIER_RECEIPT_FIELDS = (
    "schema",
    "session_id",
    "turn_id",
    "fact_id",
    "memory_id",
    "revision_id",
    "evidence_hash",
    "promotion_batch_digest",
    "verifier_id",
    "source_digest",
    "result",
    "observed_at",
)
_SHA256_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CLAIM_SCOPES = frozenset({"private", "agent", "org", "public"})
_CLAIM_V2_ONLY_AUTHORITY_FIELDS = frozenset(
    {
        "memory_id",
        "revision_id",
        "valid_from",
        "valid_to",
        "verify_before_act",
        "promotion_batch_digest",
        "parent_revision_ids",
        "revokes_revision_ids",
    }
)


class ClaimAttestationError(ValueError):
    """A claim revision cannot be represented by the signed v2 contract."""


# --- canonicalization --------------------------------------------------------
def _canonical_json(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, compact separators, UTF-8.

    Stable across re-serialization so a fact that round-trips through json
    dump/load produces an identical signing payload."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_contract_json(obj: Any) -> bytes:
    """Canonical bytes for portable memory, claim, and receipt contracts."""

    def validate_numbers(item: Any) -> None:
        if isinstance(item, bool) or item is None or isinstance(item, (str, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ClaimAttestationError("canonical numbers must be finite")
            if item == 0.0 and math.copysign(1.0, item) < 0:
                raise ClaimAttestationError(
                    "canonical numbers must not use negative zero"
                )
            rendered = json.dumps(item, allow_nan=False)
            if "e" in rendered.lower() or rendered.endswith(".0"):
                raise ClaimAttestationError(
                    "fractional canonical numbers use plain shortest decimal form"
                )
            return
        if isinstance(item, dict):
            for nested in item.values():
                validate_numbers(nested)
            return
        if isinstance(item, (list, tuple)):
            for nested in item:
                validate_numbers(nested)

    validate_numbers(obj)
    return _canonical_json(obj)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_fact_core(fact: dict[str, Any]) -> dict[str, Any]:
    """The CORE content a signature commits to: id + kind + content.

    These three define what the fact *asserts*. Mutating any of them (the F5
    attack: poisoning the injected claim) changes this hash and breaks the
    signature."""
    return {
        "id": fact.get("id", ""),
        "kind": fact.get("kind", ""),
        "content": fact.get("content", ""),
    }


def source_anchor(fact: dict[str, Any]) -> Any:
    """The provenance anchor: the evidence pointer(s) {event_id, path, line}.

    Kept distinct from the core so the verifier can later distinguish a tampered
    claim from a tampered provenance trail."""
    return fact.get("evidence", [])


def canonical_fact_hash(fact: dict[str, Any]) -> str:
    return _sha256_hex(_canonical_json(canonical_fact_core(fact)))


def source_hash(fact: dict[str, Any]) -> str:
    return _sha256_hex(_canonical_json(source_anchor(fact)))


def _sha256_id(data: bytes) -> str:
    return "sha256:" + _sha256_hex(data)


def content_hash_v2(fact: dict[str, Any]) -> str:
    """Hash the exact claim text used by the v2 authority contract."""
    content = fact.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ClaimAttestationError("content must be non-empty text")
    return _sha256_id(content.encode("utf-8"))


def evidence_hash_v2(fact: dict[str, Any]) -> str:
    """Hash the complete evidence-anchor array used for promotion."""
    evidence = fact.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ClaimAttestationError("evidence must be a non-empty list")
    try:
        return _sha256_id(_canonical_json(evidence))
    except (TypeError, ValueError) as exc:
        raise ClaimAttestationError("evidence must be canonical JSON") from exc


def _required_text(fact: dict[str, Any], field: str) -> str:
    value = fact.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ClaimAttestationError(f"{field} must be non-empty text")
    return value


def _revision_id(fact: dict[str, Any], field: str) -> str:
    value = _required_text(fact, field)
    if not _SHA256_ID_RE.fullmatch(value):
        raise ClaimAttestationError(f"{field} must be a sha256 revision id")
    return value


def _revision_ids_v2(fact: dict[str, Any], field: str) -> list[str]:
    values = fact.get(field, [])
    if not isinstance(values, list) or any(
        not isinstance(value, str) or not _SHA256_ID_RE.fullmatch(value)
        for value in values
    ):
        raise ClaimAttestationError(f"{field} must contain sha256 revision ids")
    if len(values) != len(set(values)):
        raise ClaimAttestationError(f"{field} contains duplicate revision ids")
    return list(values)


def _claim_timestamp(fact: dict[str, Any], field: str, *, nullable: bool = False):
    value = fact.get(field)
    if nullable and value is None:
        return None, None
    if not isinstance(value, str):
        raise ClaimAttestationError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ClaimAttestationError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ClaimAttestationError(f"{field} must include a timezone")
    canonical = parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    if value != canonical:
        raise ClaimAttestationError(
            f"{field} must use canonical UTC with six fractional digits"
        )
    return value, parsed


def claim_payload_v2(fact: dict[str, Any]) -> dict[str, Any]:
    """Build and validate every immutable field that changes claim authority.

    Human-readable ``status`` is deliberately absent. Authority is retired only
    by a separately signed record whose ``revokes_revision_ids`` names the
    revision being replaced or revoked.
    """
    memory_id = _required_text(fact, "memory_id")
    try:
        uuid.UUID(memory_id)
    except (ValueError, AttributeError) as exc:
        raise ClaimAttestationError("memory_id must be a UUID") from exc

    revision_id = _revision_id(fact, "revision_id")
    fact_id = _required_text(fact, "id")
    kind = _required_text(fact, "kind")
    category = _required_text(fact, "category")
    content_hash = content_hash_v2(fact)
    evidence_hash = evidence_hash_v2(fact)
    if "content_hash" in fact and fact["content_hash"] != content_hash:
        raise ClaimAttestationError("content_hash does not match content")
    if "evidence_hash" in fact and fact["evidence_hash"] != evidence_hash:
        raise ClaimAttestationError("evidence_hash does not match evidence")

    scope = fact.get("scope")
    if scope not in _CLAIM_SCOPES:
        raise ClaimAttestationError("scope is not recognized")
    confidence = fact.get("confidence")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or (isinstance(confidence, float) and not math.isfinite(confidence))
        or not 0 <= confidence <= 1
    ):
        raise ClaimAttestationError("confidence must be a finite number from 0 to 1")

    source_time, _ = _claim_timestamp(fact, "source_time")
    valid_from, valid_from_dt = _claim_timestamp(fact, "valid_from")
    valid_to, valid_to_dt = _claim_timestamp(fact, "valid_to", nullable=True)
    if valid_to_dt is not None and valid_to_dt <= valid_from_dt:
        raise ClaimAttestationError("valid_to must be later than valid_from")

    verify_before_act = fact.get("verify_before_act")
    if not isinstance(verify_before_act, bool):
        raise ClaimAttestationError("verify_before_act must be true or false")
    promotion_batch_digest = _required_text(fact, "promotion_batch_digest")
    if not _SHA256_ID_RE.fullmatch(promotion_batch_digest):
        raise ClaimAttestationError("promotion_batch_digest must be a sha256 digest")

    return {
        "schema": CLAIM_ATTESTATION_V2_SCHEMA,
        "memory_id": memory_id,
        "revision_id": revision_id,
        "fact_id": fact_id,
        "kind": kind,
        "category": category,
        "content_hash": content_hash,
        "evidence_hash": evidence_hash,
        "scope": scope,
        "confidence": confidence,
        "source_time": source_time,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "verify_before_act": verify_before_act,
        "promotion_batch_digest": promotion_batch_digest,
        "parent_revision_ids": _revision_ids_v2(fact, "parent_revision_ids"),
        "revokes_revision_ids": _revision_ids_v2(fact, "revokes_revision_ids"),
    }


def canonical_claim_payload_v2(fact: dict[str, Any]) -> bytes:
    """Return the deterministic JSON bytes committed by a v2 signature."""
    return canonical_contract_json(claim_payload_v2(fact))


def verifier_receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    """Validate the exact payload emitted by a trusted live verifier.

    A receipt is deliberately narrower than a general event envelope: it binds
    one real provider session and turn to one signed claim revision and one
    live evidence anchor. Extra fields are rejected so every accepted byte is
    part of the signature contract.
    """
    if not isinstance(receipt, dict) or set(receipt) != set(VERIFIER_RECEIPT_FIELDS):
        raise ClaimAttestationError("verifier receipt fields do not match schema")
    if receipt.get("schema") != VERIFIER_RECEIPT_SCHEMA:
        raise ClaimAttestationError("verifier receipt schema is not recognized")
    for field in (
        "session_id",
        "turn_id",
        "fact_id",
        "verifier_id",
        "source_digest",
    ):
        _required_text(receipt, field)
    memory_id = _required_text(receipt, "memory_id")
    try:
        uuid.UUID(memory_id)
    except (ValueError, AttributeError) as exc:
        raise ClaimAttestationError("memory_id must be a UUID") from exc
    _revision_id(receipt, "revision_id")
    _revision_id(receipt, "evidence_hash")
    _revision_id(receipt, "promotion_batch_digest")
    if receipt.get("result") != "verified":
        raise ClaimAttestationError("verifier receipt result must be verified")
    _claim_timestamp(receipt, "observed_at")
    return {field: receipt[field] for field in VERIFIER_RECEIPT_FIELDS}


def canonical_verifier_receipt_payload(receipt: dict[str, Any]) -> bytes:
    """Return the deterministic bytes committed by a verifier receipt."""
    return canonical_contract_json(verifier_receipt_payload(receipt))


def _signed_payload(fact_hash: str, src_hash: str, parent_hashes: list[str]) -> bytes:
    """The exact bytes that get signed.

    Includes the fact hash, the source hash, and the SORTED canonical hashes of
    every parent fact (Merkle-style). Sorting makes ancestry order-independent;
    a parent's hash is computed from the parent fact's own core, so editing a
    parent changes the child's payload -> child verifies parent-suspect."""
    body = {
        "fact_hash": fact_hash,
        "source_hash": src_hash,
        "parent_hashes": sorted(parent_hashes),
    }
    return _DOMAIN + _canonical_json(body)


# --- key management ----------------------------------------------------------
def key_fingerprint(material: bytes, alg: str) -> str:
    """Short, stable id derived from the key material (never the secret itself
    for HMAC: we fingerprint a one-way hash, so key_id leaks nothing)."""
    digest = hashlib.sha256(alg.encode("utf-8") + b":" + material).hexdigest()
    return f"{alg}:{digest[:16]}"


class SigningKey:
    """A signing/verification key pair. Ed25519 when available, else HMAC.

    Never logs or serializes the private material into facts."""

    def __init__(self, alg: str, *, ed_private=None, ed_public=None, hmac_secret: bytes | None = None):
        self.alg = alg
        self._ed_private = ed_private
        self._ed_public = ed_public
        self._hmac_secret = hmac_secret
        if alg == ALG_ED25519:
            pub_bytes = ed_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self._pub_bytes = pub_bytes
            self.key_id = key_fingerprint(pub_bytes, alg)
        else:
            self._pub_bytes = None
            # Fingerprint a hash of the secret, not the secret, so key_id is safe
            # to embed in every attestation.
            self.key_id = key_fingerprint(hashlib.sha256(hmac_secret).digest(), alg)

    def cache_key_material(self) -> bytes | None:
        """Secret bytes that key the verification-cache MAC (see cache_digest).

        For HMAC it is the shared secret; for Ed25519 it is the private-key
        bytes when this object can sign. Public-only Ed25519 keys return None
        so the cache short-circuit is skipped: the public key is not
        secret, and keying the MAC on it let a store-dir writer forge VALID
        cache entries. key_id alone does NOT suffice either: it is a
        truncated one-way fingerprint that is public in every attestation.
        """
        if self.alg == ALG_ED25519:
            if self._ed_private is None:
                return None
            return self._ed_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        return self._hmac_secret

    # -- signing/verifying primitives --
    def sign_bytes(self, payload: bytes) -> str:
        if self.alg == ALG_ED25519:
            return self._ed_private.sign(payload).hex()
        return hmac.new(self._hmac_secret, payload, hashlib.sha256).hexdigest()

    def verify_bytes(self, payload: bytes, signature_hex: str) -> bool:
        try:
            sig = bytes.fromhex(signature_hex)
        except (ValueError, TypeError):
            return False
        if self.alg == ALG_ED25519:
            try:
                self._ed_public.verify(sig, payload)
                return True
            except Exception:
                return False
        expected = hmac.new(self._hmac_secret, payload, hashlib.sha256).digest()
        return hmac.compare_digest(expected, sig)


def _generate_key(alg: str | None = None) -> SigningKey:
    use_ed = _HAVE_CRYPTOGRAPHY if alg is None else (alg == ALG_ED25519)
    if use_ed and _HAVE_CRYPTOGRAPHY:
        priv = Ed25519PrivateKey.generate()
        return SigningKey(ALG_ED25519, ed_private=priv, ed_public=priv.public_key())
    # HMAC fallback: 32 bytes of CSPRNG entropy.
    secret = secrets.token_bytes(32)
    return SigningKey(ALG_HMAC, hmac_secret=secret)


def _write_key(key: SigningKey, key_path: Path, pub_path: Path) -> None:
    """Persist private key 0600 and public key 0600 via secure-perm helpers.

    Stored as JSON with the alg recorded so load can reconstruct without
    guessing. Private material is written ONLY to key_path, never logged."""
    if key.alg == ALG_ED25519:
        priv_raw = key._ed_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = key._ed_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        priv_doc = {"alg": ALG_ED25519, "key_id": key.key_id, "private_key": priv_raw.hex()}
        pub_doc = {"alg": ALG_ED25519, "key_id": key.key_id, "public_key": pub_raw.hex()}
    else:
        priv_doc = {"alg": ALG_HMAC, "key_id": key.key_id, "secret": key._hmac_secret.hex()}
        # HMAC is symmetric; the "public" file records only the verifying alg +
        # key_id + the same secret (verification needs it). It is also 0600.
        pub_doc = {"alg": ALG_HMAC, "key_id": key.key_id, "secret": key._hmac_secret.hex()}

    secure_write_text(key_path, json.dumps(priv_doc, indent=2))
    secure_write_text(pub_path, json.dumps(pub_doc, indent=2))


def _load_key_from_doc(doc: dict[str, Any]) -> SigningKey:
    alg = doc.get("alg")
    if alg == ALG_ED25519:
        if not _HAVE_CRYPTOGRAPHY:
            raise RuntimeError(
                "key is Ed25519 but cryptography is unavailable; cannot load"
            )
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(doc["private_key"]))
        return SigningKey(ALG_ED25519, ed_private=priv, ed_public=priv.public_key())
    if alg == ALG_HMAC:
        return SigningKey(ALG_HMAC, hmac_secret=bytes.fromhex(doc["secret"]))
    raise RuntimeError(f"unknown key alg: {alg!r}")


def load_or_create_key(
    key_path: Path = DEFAULT_KEY_PATH,
    pub_path: Path = DEFAULT_PUB_PATH,
    *,
    alg: str | None = None,
    create: bool = True,
) -> SigningKey:
    """Load the signing key, auto-generating one if absent (when create=True).

    The generated algorithm follows availability: Ed25519 if cryptography is
    importable, else HMAC-SHA256. Pass ``alg`` to force one (used by tests)."""
    key_path = Path(key_path)
    pub_path = Path(pub_path)
    if key_path.exists():
        doc = json.loads(key_path.read_text(encoding="utf-8"))
        return _load_key_from_doc(doc)
    if not create:
        raise FileNotFoundError(f"signing key not found at {key_path}")
    secure_mkdir(key_path.parent)
    key = _generate_key(alg)
    _write_key(key, key_path, pub_path)
    return key


def load_public_key(pub_path: Path = DEFAULT_PUB_PATH) -> SigningKey:
    """Load a verification-only view of the key.

    For Ed25519 this needs only the public key; for HMAC the same secret is
    required to verify (symmetric)."""
    pub_path = Path(pub_path)
    if not pub_path.exists():
        raise FileNotFoundError(f"public key not found at {pub_path}")
    doc = json.loads(pub_path.read_text(encoding="utf-8"))
    alg = doc.get("alg")
    if alg == ALG_ED25519:
        if not _HAVE_CRYPTOGRAPHY:
            raise RuntimeError(
                "public key is Ed25519 but cryptography is unavailable; cannot verify"
            )
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(doc["public_key"]))
        # Verification-only: no private key.
        return SigningKey(ALG_ED25519, ed_private=None, ed_public=pub)
    if alg == ALG_HMAC:
        return SigningKey(ALG_HMAC, hmac_secret=bytes.fromhex(doc["secret"]))
    raise RuntimeError(f"unknown key alg: {alg!r}")


def resolve_key_paths(
    key_path: Path | None = None,
    pub_path: Path | None = None,
    *,
    store_dir: Path | None = None,
) -> tuple[Path, Path]:
    """Resolve (private, public) key paths: explicit args > env > defaults.

    ``store_dir`` (rebuild) defaults to ``store_dir/signing-key`` instead of
    ``~/.nock-brain``. Empty env values fall through. This is the single
    resolver for sign-facts, verify-facts, rebuild-store, and recall.
    """
    default_key = (
        Path(store_dir) / "signing-key" if store_dir is not None else DEFAULT_KEY_PATH
    )
    default_pub = (
        Path(store_dir) / "signing-key.pub" if store_dir is not None else DEFAULT_PUB_PATH
    )
    env_key = os.environ.get("NOCKBRAIN_SIGNING_KEY", "").strip()
    env_pub = os.environ.get("NOCKBRAIN_SIGNING_PUB", "").strip()
    resolved_key = Path(key_path) if key_path is not None else Path(env_key or default_key)
    resolved_pub = Path(pub_path) if pub_path is not None else Path(env_pub or default_pub)
    return resolved_key, resolved_pub


def resolve_signing_key(
    key_path: Path | None = None,
    pub_path: Path | None = None,
    *,
    store_dir: Path | None = None,
    create: bool = False,
) -> SigningKey | None:
    """Load (or optionally create) the signing key at the resolved paths.

    Returns None when the key is missing or unloadable and ``create`` is False.
    """
    kp, pp = resolve_key_paths(key_path, pub_path, store_dir=store_dir)
    try:
        return load_or_create_key(kp, pp, create=create)
    except (FileNotFoundError, RuntimeError, ValueError, KeyError, OSError,
            json.JSONDecodeError, TypeError):
        return None


def resolve_verify_key(
    key_path: Path | None = None,
    pub_path: Path | None = None,
    *,
    store_dir: Path | None = None,
) -> tuple[SigningKey | None, str | None]:
    """Load the verification key used by recall, verify-facts, and health.

    Path order matches ``resolve_key_paths``. Prefers the private key when
    present so the verify-cache MAC has secret material; falls back
    to the public key (verify-only; Ed25519 cache short-circuit disabled).

    Exception: if the operator named only a public key via
    ``NOCKBRAIN_SIGNING_PUB`` (and no ``NOCKBRAIN_SIGNING_KEY`` / CLI
    ``--key``), do not fall through to a default private key of a different
    identity. recall-eval uses this to verify the committed fixture.

    Returns ``(key, error)``. ``error`` is set when a key file existed but
    could not be loaded. Both None means signing was never set up.
    """
    kp, pp = resolve_key_paths(key_path, pub_path, store_dir=store_dir)
    env_key = os.environ.get("NOCKBRAIN_SIGNING_KEY", "").strip()
    env_pub = os.environ.get("NOCKBRAIN_SIGNING_PUB", "").strip()
    skip_private = (
        key_path is None
        and not env_key
        and bool(env_pub)
        and pub_path is None
    )
    errors: list[str] = []
    if not skip_private and kp.exists():
        try:
            return load_or_create_key(kp, pp, create=False), None
        except Exception as exc:  # noqa: BLE001 - never break callers on key trouble
            errors.append(f"{kp}: {exc}")
    if pp.exists():
        try:
            return load_public_key(pp), None
        except Exception as exc:  # noqa: BLE001 - never break callers on key trouble
            errors.append(f"{pp}: {exc}")
    if errors:
        return None, "; ".join(errors)
    return None, None


# --- signing facts -----------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parent_hashes(parent_ids: list[str], facts_by_id: dict[str, dict[str, Any]]) -> list[str]:
    """Canonical hash of each parent fact's core, for the Merkle commitment.

    A parent referenced but absent from the store hashes its id alone (so the
    commitment is still defined and a later-added/altered parent will mismatch)."""
    hashes = []
    for pid in parent_ids:
        parent = facts_by_id.get(pid)
        if parent is not None:
            hashes.append(canonical_fact_hash(parent))
        else:
            # Absent parent: commit to a sentinel derived from the id so the
            # child still has a stable, verifiable ancestry hash.
            hashes.append(_sha256_hex(_canonical_json({"absent_parent_id": pid})))
    return hashes


def _parent_set_moved(
    parent_ids: list[str], facts_by_id: dict[str, dict[str, Any]]
) -> bool:
    """True iff a listed parent is absent, or a present parent's current core
    no longer matches its own committed hash.

    Independent of the child's signature: ``att["signature"]`` is
    attacker-mutable, so a failed verify cannot by itself prove ancestry
    moved. PARENT_SUSPECT is only claimed when this evidence exists."""
    for pid in parent_ids:
        parent = facts_by_id.get(pid)
        if parent is None:
            return True
        att = parent.get("attestation") if isinstance(parent, dict) else None
        committed = att.get("canonical_fact_hash") if isinstance(att, dict) else None
        if isinstance(committed, str) and committed:
            if canonical_fact_hash(parent) != committed:
                return True
    return False


def attest_fact(
    fact: dict[str, Any],
    key: SigningKey,
    *,
    facts_by_id: dict[str, dict[str, Any]] | None = None,
    parent_fact_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Return the attestation envelope for ``fact`` signed by ``key``.

    ``parent_fact_ids`` defaults to any already present on the fact's
    attestation, or an explicit ``parent_fact_ids`` field on the fact itself."""
    facts_by_id = facts_by_id or {}
    if parent_fact_ids is None:
        existing = fact.get("attestation", {}).get("parent_fact_ids")
        parent_fact_ids = existing if existing is not None else fact.get("parent_fact_ids", [])
    parent_fact_ids = list(parent_fact_ids or [])

    fact_hash = canonical_fact_hash(fact)
    src_hash = source_hash(fact)
    p_hashes = _parent_hashes(parent_fact_ids, facts_by_id)
    payload = _signed_payload(fact_hash, src_hash, p_hashes)
    signature = key.sign_bytes(payload)

    return {
        "fact_id": fact.get("id", ""),
        "canonical_fact_hash": fact_hash,
        "source_hash": src_hash,
        "alg": key.alg,
        "key_id": key.key_id,
        "signature": signature,
        "parent_fact_ids": parent_fact_ids,
        "signed_at": _now_iso(),
    }


def sign_fact(
    fact: dict[str, Any],
    key: SigningKey,
    *,
    facts_by_id: dict[str, dict[str, Any]] | None = None,
    parent_fact_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Sign ``fact`` in place: attach the attestation envelope and return it."""
    fact["attestation"] = attest_fact(
        fact, key, facts_by_id=facts_by_id, parent_fact_ids=parent_fact_ids
    )
    return fact


def is_v2_claim_fact(fact: dict[str, Any]) -> bool:
    """True iff ``fact`` carries claim authority that MUST be signed with the v2
    contract (``sign_claim_fact_v2``) rather than the legacy ``sign_fact``.

    Two signals, either sufficient:

    - its attestation already declares the v2 schema, or
    - it carries any of the v2-only authority fields.

    This is the routing predicate: ``verify_fact``'s legacy branch rejects
    (``TAMPERED``) any fact that carries a v2-only authority field (see
    ``_CLAIM_V2_ONLY_AUTHORITY_FIELDS.intersection(fact)`` there), so bulk-signing
    such a fact with ``sign_fact`` drops it out of recall. Callers that sign a
    whole store (``sign_facts``, ``sign-facts.py``) and ``edit-fact.py`` share
    this one predicate so the rule lives in exactly one place."""
    if not isinstance(fact, dict):
        return False
    att = fact.get("attestation")
    if isinstance(att, dict) and att.get("schema") == CLAIM_ATTESTATION_V2_SCHEMA:
        return True
    return bool(_CLAIM_V2_ONLY_AUTHORITY_FIELDS.intersection(fact))


def sign_facts(
    facts: list[dict[str, Any]],
    key: SigningKey,
    *,
    only: "Callable[[dict[str, Any]], bool] | None" = None,
) -> list[dict[str, Any]]:
    """Sign every fact in a store, routing each to the correct contract.

    ``only`` (a predicate over the fact) restricts which facts get a new
    attestation while parent hashing still sees the whole store. Rebuild
    uses it to leave already-VALID attestations byte-stable (no nightly
    ``signed_at`` churn). Default: every fact.

    A fact carrying v2 claim authority (``is_v2_claim_fact``) is signed with
    ``sign_claim_fact_v2``; every other fact keeps the legacy ``sign_fact``
    scheme. This matters because ``verify_fact`` rejects a v2-authority fact that
    was legacy-signed as ``TAMPERED``: bulk-signing the whole store with
    ``sign_fact`` would silently drop those facts from recall. A malformed
    v2-authority fact makes ``sign_claim_fact_v2`` raise ``ClaimAttestationError``
    here (fail-closed) rather than mint a fact that will not verify.

    Legacy signing is single-pass over a stable id map: parent hashing uses
    ``canonical_fact_hash`` which does not depend on the attestation, so the
    parents' CORE is committed independent of signing order."""
    facts_by_id = {f.get("id", ""): f for f in facts if isinstance(f, dict)}
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        if only is not None and not only(fact):
            continue
        if is_v2_claim_fact(fact):
            sign_claim_fact_v2(fact, key)
        else:
            sign_fact(fact, key, facts_by_id=facts_by_id)
    return facts


def attest_claim_fact_v2(
    fact: dict[str, Any], key: SigningKey
) -> dict[str, Any]:
    """Return a signed envelope binding the complete v2 authority payload."""
    payload = claim_payload_v2(fact)
    signature = key.sign_bytes(
        CLAIM_ATTESTATION_V2_DOMAIN + canonical_contract_json(payload)
    )
    return {
        "schema": CLAIM_ATTESTATION_V2_SCHEMA,
        "payload": payload,
        "alg": key.alg,
        "key_id": key.key_id,
        "signature": signature,
        "signed_at": _now_iso(),
    }


def sign_claim_fact_v2(
    fact: dict[str, Any], key: SigningKey
) -> dict[str, Any]:
    """Sign a claim-authority fact in place using the v2 contract."""
    fact["attestation"] = attest_claim_fact_v2(fact, key)
    return fact


def sign_verifier_receipt(
    payload: dict[str, Any], key: SigningKey
) -> dict[str, Any]:
    """Sign one trusted live-verifier result for an exact session and turn.

    Operational callers must keep the private key outside the agent's process. The
    returned record is ready for the append-only receipt store consumed by
    Claim Guard; unsigned or agent-authored records cannot pass verification.
    """
    validated = verifier_receipt_payload(payload)
    signed = dict(validated)
    signed.update(
        {
            "alg": key.alg,
            "key_id": key.key_id,
            "signature": key.sign_bytes(
                VERIFIER_RECEIPT_DOMAIN + canonical_contract_json(validated)
            ),
        }
    )
    return signed


def verify_verifier_receipt(
    receipt: dict[str, Any], key: SigningKey | None
) -> bool:
    """Verify a strict verifier-receipt envelope under its own domain."""
    if key is None or not isinstance(receipt, dict):
        return False
    payload = {
        field: receipt.get(field) for field in VERIFIER_RECEIPT_FIELDS
    }
    try:
        validated = verifier_receipt_payload(payload)
    except ClaimAttestationError:
        return False
    if set(receipt) != set(VERIFIER_RECEIPT_FIELDS) | {
        "alg",
        "key_id",
        "signature",
    }:
        return False
    if receipt.get("alg") != key.alg or receipt.get("key_id") != key.key_id:
        return False
    signature = receipt.get("signature")
    if not isinstance(signature, str):
        return False
    return key.verify_bytes(
        VERIFIER_RECEIPT_DOMAIN + canonical_contract_json(validated), signature
    )


# --- verification ------------------------------------------------------------
# Verification status constants.
VALID = "valid"
TAMPERED = "tampered"
UNSIGNED = "unsigned"
PARENT_SUSPECT = "parent-suspect"

# Domain separation for verification-cache digests (distinct from _DOMAIN so a
# cache digest can never be confused with signable material). The version
# suffix is bumped whenever the digest scheme changes so stale sidecars are
# rejected wholesale by _verify_cache.CACHE_VERSION; v2 switched the digest
# from a plain sha256 of public inputs to an HMAC keyed under the verifying key
# material (see cache_digest) to close a sidecar-forgery bypass. v3 keys the
# Ed25519 HMAC on private-key bytes instead of the public key.
_CACHE_DOMAIN = b"nockbrain-verify-cache-v3"


def is_cacheable_signature(signature_hex: Any) -> bool:
    """True iff ``signature_hex`` is a hex string verify_bytes could parse.

    Gate for the cache path: a non-str or non-hex signature (attacker-writable
    facts.json can carry either: a JSON number, a list, or a string with a
    lone surrogate/NUL) must skip caching and fall straight through to
    verify_bytes, which returns False -> TAMPERED. Mirrors verify_bytes'
    ``bytes.fromhex`` exactly, so a signature is cacheable iff it is verifiable,
    and cache_digest never sees bytes that would crash ``.encode`` or make its
    field encoding ambiguous."""
    if not isinstance(signature_hex, str):
        return False
    try:
        bytes.fromhex(signature_hex)
        return True
    except ValueError:
        return False


def cache_digest(key: SigningKey, signature_hex: str, payload: bytes,
                 status: str = VALID) -> str:
    """Digest naming one signature-op determination, for the recall hot
    path's sidecar cache (_verify_cache). It binds everything the proof
    depended on (algorithm, key, signature, and the exact signed payload,
    which itself embeds the committed fact/source hashes and the CURRENT
    parent hashes), so any change to any of them yields a different digest,
    a cache miss, and a real verification.

    VALID proofs use the historical preimage (no status field) so existing
    sidecars keep hitting. Non-VALID determinations (PARENT_SUSPECT, or
    TAMPERED when the public-key op itself failed) insert ``status`` before
    the payload: the sidecar is attacker-writable, and binding the outcome
    into the HMAC means rewriting a cached PARENT_SUSPECT digest cannot mint
    a VALID hit. A later store change that repairs ancestry changes the
    payload's embedded parent hashes, so the digest misses and re-verifies.

    It is an HMAC keyed under ``key.cache_key_material()`` (NOT a bare hash of
    public inputs): every non-keyed input here (alg, the public key_id
    fingerprint, the signature, the payload, the status label) is computable
    by anyone who can read facts.json. Keying the digest under secret
    material (Ed25519 private bytes, or the HMAC shared secret) means a
    forged sidecar entry cannot mint a VALID result without read access to
    the private key file. Public-only Ed25519 keys have no cache material;
    callers must skip the short-circuit. ``signature_hex`` is a
    caller-validated hex string (see is_cacheable_signature), so the
    NUL-joined field encoding is unambiguous (hex/alg/fingerprint/status
    bytes contain no NUL and the variable-length payload comes last)."""
    fields = [
        _CACHE_DOMAIN,
        key.alg.encode("utf-8"),
        key.key_id.encode("utf-8"),
        signature_hex.encode("utf-8"),
    ]
    if status != VALID:
        # Closed enum (tampered / parent-suspect): ASCII, no NUL.
        fields.append(status.encode("utf-8"))
    fields.append(payload)
    preimage = b"\0".join(fields)
    material = key.cache_key_material()
    if not material:
        raise ValueError("cache_digest requires secret cache-key material")
    return hmac.new(material, preimage, hashlib.sha256).hexdigest()


def _cached_signature_status(
    key: SigningKey,
    signature: str,
    payload: bytes,
    verified_cache,
    fail_status: str,
) -> str:
    """Run (or reuse) the public-key operation for ``payload``.

    Returns VALID if the signature verifies, otherwise ``fail_status``
    (caller-chosen: PARENT_SUSPECT only when ancestry is independently
    shown to have moved, else TAMPERED). ``verified_cache`` skips a
    previously recorded determination for this (key, signature, payload)
    tuple; committed-hash / freshness checks are the caller's job and
    must already have run.
    """
    digest_valid = None
    digest_fail = None
    can_cache = (
        verified_cache is not None
        and is_cacheable_signature(signature)
        and key.cache_key_material() is not None
    )
    if can_cache:
        digest_valid = cache_digest(key, signature, payload)
        if verified_cache.hit(digest_valid):
            return VALID
        digest_fail = cache_digest(key, signature, payload, fail_status)
        if verified_cache.hit(digest_fail):
            return fail_status
    if key.verify_bytes(payload, signature):
        if digest_valid is not None:
            verified_cache.add(digest_valid)
        return VALID
    if digest_fail is not None:
        verified_cache.add(digest_fail)
    return fail_status


def verify_fact(
    fact: dict[str, Any],
    key: SigningKey | None,
    *,
    facts_by_id: dict[str, dict[str, Any]] | None = None,
    verified_cache=None,
) -> str:
    """Verify a single fact's attestation. Returns one of the status constants.

    - UNSIGNED: no attestation present (backward-compat: still loads elsewhere).
    - TAMPERED: the fact's own core or source anchor no longer matches the
      signed hashes, or the signature does not verify under the key.
    - PARENT_SUSPECT: the fact itself is intact, but a parent fact's current
      core no longer matches what the child committed to (Merkle break).
    - VALID: signature verifies and all committed hashes match.

    ``verified_cache`` (a _verify_cache.VerifiedSignatureCache, or anything
    with hit/add) short-circuits ONLY the public-key signature operation, for
    (key, signature, payload) triples this store has already resolved: VALID,
    PARENT_SUSPECT, or signature-fail TAMPERED. The committed-hash comparisons
    below run unconditionally either way, so a tampered fact is still caught
    with a warm cache. UNSIGNED and committed-hash TAMPERED are not cached
    (no signature op to skip)."""
    facts_by_id = facts_by_id or {}
    if "attestation" not in fact:
        return UNSIGNED
    att = fact.get("attestation")
    if not isinstance(att, dict):
        return TAMPERED
    signature = att.get("signature")
    if not isinstance(signature, str) or not signature:
        return TAMPERED
    if key is None:
        # No key to verify against -> cannot affirm; treat as tampered/unverifiable.
        return TAMPERED

    schema = att.get("schema")
    if schema is not None:
        if schema != CLAIM_ATTESTATION_V2_SCHEMA:
            return TAMPERED
        try:
            payload = claim_payload_v2(fact)
        except ClaimAttestationError:
            return TAMPERED
        if att.get("payload") != payload:
            return TAMPERED
        if key.alg != att.get("alg") or key.key_id != att.get("key_id"):
            return TAMPERED
        signed_payload = CLAIM_ATTESTATION_V2_DOMAIN + canonical_contract_json(
            payload
        )
        return _cached_signature_status(
            key, signature, signed_payload, verified_cache, TAMPERED
        )

    if _CLAIM_V2_ONLY_AUTHORITY_FIELDS.intersection(fact):
        return TAMPERED
    legacy_text_fields = (
        "fact_id",
        "canonical_fact_hash",
        "source_hash",
        "alg",
        "key_id",
        "signature",
        "signed_at",
    )
    if any(not isinstance(att.get(field), str) or not att[field] for field in legacy_text_fields):
        return TAMPERED
    parent_fact_ids = att.get("parent_fact_ids")
    if not isinstance(parent_fact_ids, list) or any(
        not isinstance(parent_id, str) or not parent_id
        for parent_id in parent_fact_ids
    ):
        return TAMPERED

    # 1. Recompute the fact's own hashes from current content and compare to the
    #    committed values. This catches the F5 content-poisoning attack.
    current_fact_hash = canonical_fact_hash(fact)
    current_src_hash = source_hash(fact)
    if current_fact_hash != att.get("canonical_fact_hash"):
        return TAMPERED
    if current_src_hash != att.get("source_hash"):
        return TAMPERED

    # 2. Recompute the signed payload using the committed hashes + CURRENT parent
    #    hashes, and verify the signature. If the signature itself fails the
    #    fact's own bytes were tampered (or wrong key) -> TAMPERED.
    parent_ids = list(parent_fact_ids)
    parent_hashes_now = _parent_hashes(parent_ids, facts_by_id)
    payload_now = _signed_payload(
        att["canonical_fact_hash"], att["source_hash"], parent_hashes_now
    )
    if key.alg != att.get("alg"):
        # Algorithm mismatch between key and attestation -> cannot have produced it.
        return TAMPERED
    # 3. Signature over payload_now. A failure is not automatically an
    #    ancestry break: att["signature"] is attacker-mutable and lives in
    #    the same store, so parent_ids being non-empty cannot distinguish
    #    "a parent was edited/revoked" from "the signature was flipped".
    #    PARENT_SUSPECT only when we independently observe a parent gone or
    #    a parent's core drifted from its own committed hash; otherwise
    #    TAMPERED. The cache records that determination (status-bound
    #    digest) so a stable Merkle-broken child does not re-run Ed25519 on
    #    every recall; a repaired parent changes payload_now -> miss ->
    #    re-verify.
    if parent_ids and _parent_set_moved(parent_ids, facts_by_id):
        fail_status = PARENT_SUSPECT
    else:
        fail_status = TAMPERED
    return _cached_signature_status(
        key, att["signature"], payload_now, verified_cache, fail_status
    )


def verify_facts(
    facts: list[dict[str, Any]],
    key: SigningKey | None,
    *,
    verified_cache=None,
) -> dict[str, Any]:
    """Verify a whole store. Returns counts + per-fact statuses.

    ``verified_cache`` (a _verify_cache.VerifiedSignatureCache, or anything
    with hit/add) is threaded into each ``verify_fact`` so caching is a
    property of verification, not of one caller. The offline auditor
    (verify-facts.py) passes None: an audit always does the full
    cryptographic pass.

    Result shape::
        {"valid": int, "tampered": int, "unsigned": int, "parent_suspect": int,
         "total": int, "statuses": [{"id":..., "status":...}, ...]}"""
    facts_by_id = {f.get("id", ""): f for f in facts if isinstance(f, dict)}
    counts = {VALID: 0, TAMPERED: 0, UNSIGNED: 0, PARENT_SUSPECT: 0}
    statuses = []
    for fact in facts:
        if not isinstance(fact, dict):
            counts[TAMPERED] += 1
            statuses.append({"id": None, "status": TAMPERED})
            continue
        status = verify_fact(fact, key, facts_by_id=facts_by_id,
                             verified_cache=verified_cache)
        counts[status] += 1
        statuses.append({"id": fact.get("id", ""), "status": status})
    return {
        "valid": counts[VALID],
        "tampered": counts[TAMPERED],
        "unsigned": counts[UNSIGNED],
        "parent_suspect": counts[PARENT_SUSPECT],
        "total": len(facts),
        "statuses": statuses,
    }
