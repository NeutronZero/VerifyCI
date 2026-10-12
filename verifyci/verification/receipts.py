"""External CI execution receipts (F2 remediation).

Verifies caller-supplied execution claims against configured trust
pins before they may corroborate Class-2 deletion hunks. Keyed trust
only (HMAC-SHA256 shared secrets, Ed25519 public keys), mirroring the
waiver posture minus the bearer fallback: an unauthenticated execution
claim is worthless, so no pin means every receipt is unverified.

This module authenticates receipts. Revision binding, target binding,
freshness, dedupe, and failure classification live at the conversion
point (`witnesses_from_receipts`); the witness predicate itself
(`deletion._has_associated_witness`) is unchanged.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ReceiptTrust:
    """Configured trust entries: key_id -> (algorithm, key material).

    HMAC entries hold shared secrets (protected: never logged, only the
    key_id is recorded). Ed25519 entries hold trusted public keys
    (hex). Unknown key ids never match.
    """
    keys: dict[str, tuple[str, Any]] = field(default_factory=dict)

    @staticmethod
    def from_env() -> "ReceiptTrust":
        """Trust pins from the environment (mirrors WAIVER_KEYS posture).

        RECEIPT_KEYS: comma-separated `key_id:secret` (hmac-sha256).
        RECEIPT_PUBLIC_KEYS: comma-separated `key_id:hex` (ed25519).
        Absent/empty -> empty trust: every receipt unverified.
        """
        from verifyci.env import get_env as _get_env
        keys: dict[str, tuple[str, Any]] = {}
        for raw in (_get_env("RECEIPT_KEYS") or "").split(","):
            raw = raw.strip()
            if not raw or ":" not in raw:
                continue
            kid, _, secret = raw.partition(":")
            kid, secret = kid.strip(), secret.strip()
            if kid and secret:
                keys[kid] = ("hmac-sha256", secret)
        for raw in (_get_env("RECEIPT_PUBLIC_KEYS") or "").split(","):
            raw = raw.strip()
            if not raw or ":" not in raw:
                continue
            kid, _, pub = raw.partition(":")
            kid, pub = kid.strip(), pub.strip()
            if kid and pub:
                keys[kid] = ("ed25519", pub)
        return ReceiptTrust(keys=keys)


_REQUIRED_STR_FIELDS = ("receipt_id", "ci_system", "run_id", "commit_sha",
                        "executed_at", "algorithm", "key_id")


def canonical_receipt_bytes(payload: dict) -> bytes:
    """Pinned canonical form for signing.

    UTF-8 of `receipt_id|ci_system|run_id|commit_sha|sorted(targets)|
    executed_at`. Any missing/empty/non-string field, empty target
    list, non-string target, or `|` inside a field is noncanonical and
    raises ValueError (reject ambiguous representations).
    """
    for name in _REQUIRED_STR_FIELDS:
        value = payload.get(name)
        if not isinstance(value, str) or not value or "|" in value:
            raise ValueError(f"noncanonical receipt field: {name}")
    targets = payload.get("targets")
    if (not isinstance(targets, list) or not targets
            or any(not isinstance(t, str) or not t or "|" in t for t in targets)):
        raise ValueError("noncanonical receipt field: targets")
    return "|".join([
        payload["receipt_id"], payload["ci_system"], payload["run_id"],
        payload["commit_sha"], ",".join(sorted(targets)), payload["executed_at"],
    ]).encode("utf-8")


def verify_receipt_signature(payload: dict, trust: ReceiptTrust) -> bool:
    """True only when the receipt authenticates under its named entry.

    Algorithm/key-type binding enforced: an hmac entry never verifies
    ed25519 and vice versa. No pin, unknown id, bad signature,
    noncanonical bytes -> False. Secrets never leave this function.
    """
    try:
        canonical = canonical_receipt_bytes(payload)
    except ValueError:
        return False
    entry = trust.keys.get(payload.get("key_id", ""))
    if entry is None:
        return False
    algorithm, material = entry
    declared = payload.get("algorithm", "")
    signature = payload.get("signature", "")
    if not isinstance(signature, str) or not signature:
        return False
    if algorithm == "hmac-sha256" and declared == "hmac-sha256":
        key_bytes = material.encode("utf-8") if isinstance(material, str) else bytes(material)
        expected = hmac.new(key_bytes, canonical, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature.lower(), expected.lower())
    if algorithm == "ed25519" and declared == "ed25519":
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub_bytes = bytes.fromhex(material) if isinstance(material, str) else bytes(material)
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
            sig_bytes = bytes.fromhex(signature) if isinstance(signature, str) else bytes(signature)
            pub.verify(sig_bytes, canonical)
            return True
        except Exception:
            return False
    return False


_FUTURE_SKEW_SECONDS = 300.0


def _parse_executed_at(value: str) -> float | None:
    import datetime
    try:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def witnesses_from_receipts(
    receipts: list[dict] | None,
    expected_commit: str | None,
    trust: ReceiptTrust,
    now: float | None = None,
) -> tuple[list, list[str]]:
    """Convert caller-supplied receipts into verified witness candidates.

    Returns (witnesses, dispositions). One witness per receipt target.
    Dispositions record every outcome (`accepted:<id>`,
    `rejected:<id>:<reason>`, `duplicate:<id>`, `skipped:<id>:<reason>`).
    Order: schema -> trust -> revision -> freshness -> targets.
    `expected_commit=None` means UNRESOLVED: nothing is evaluated.
    Target-entity relevance is enforced later by the (unchanged)
    witness predicate against each hunk's enclosing entity.
    """
    import time as _time
    from verifyci.contracts.verification_ir import ExecutionWitness
    if now is None:
        now = _time.time()
    out: list = []
    dispositions: list[str] = []
    if not receipts:
        return out, dispositions
    if expected_commit is None:
        for i, payload in enumerate(receipts):
            rid = payload.get("receipt_id") if isinstance(payload, dict) else None
            dispositions.append(f"skipped:{rid or f'#{i}'}:revision_unresolved")
        return out, dispositions
    seen_ids: set[str] = set()
    for i, payload in enumerate(receipts):
        rid = payload.get("receipt_id") if isinstance(payload, dict) else None
        label = rid or f"#{i}"
        if not isinstance(payload, dict):
            dispositions.append(f"rejected:{label}:receipt_malformed")
            continue
        if rid is None or rid in seen_ids:
            dispositions.append(f"duplicate:{label}" if rid else f"rejected:{label}:receipt_malformed")
            continue
        try:
            canonical_receipt_bytes(payload)
        except ValueError:
            dispositions.append(f"rejected:{label}:receipt_malformed")
            continue
        for target in payload["targets"]:
            if "/" in target or "\\" in target or not target.strip() or any(
                    ch.isspace() for ch in target):
                dispositions.append(f"rejected:{label}:receipt_malformed")
                break
        else:
            if not verify_receipt_signature(payload, trust):
                dispositions.append(f"rejected:{label}:receipt_untrusted")
                continue
            if payload["commit_sha"] != expected_commit:
                dispositions.append(f"rejected:{label}:receipt_stale")
                continue
            executed = _parse_executed_at(payload["executed_at"])
            if executed is None:
                dispositions.append(f"rejected:{label}:receipt_malformed")
                continue
            if executed > now + _FUTURE_SKEW_SECONDS:
                dispositions.append(f"rejected:{label}:receipt_time_anomaly")
                continue
            seen_ids.add(rid)
            for target in sorted(set(payload["targets"])):
                out.append(ExecutionWitness(
                    witness_id=f"{rid}:{target}",
                    test_file=f"{payload['ci_system']}:{payload['run_id']}",
                    target_entity_id=target,
                    target_file=None,
                    is_general_regression=False,
                    association_method="ci_receipt",
                    execution_receipt_id=rid,
                    execution_verified=True,
                ))
            dispositions.append(f"accepted:{label}")
            continue
        continue
    return out, dispositions
