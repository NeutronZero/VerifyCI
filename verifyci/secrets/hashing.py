"""Content-addressing and cryptographic hashing conventions for VerifyCI secret detection."""
from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from verifyci.secrets.contracts import SecretRule


def compute_source_hash(text: str) -> str:
    """Canonical SHA-256 hash of a source line or fragment."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_finding_fingerprint(rule_id: str, raw_secret: str) -> str:
    """Content-bound fingerprint for a detected secret.
    
    Identifies the underlying credential content deterministically without
    binding to transient line numbers or storing the raw secret in plain view.
    """
    normalized = raw_secret.strip()
    payload = f"{rule_id}\x1f{normalized}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def compute_rule_config_hash(rules: Sequence[SecretRule]) -> str:
    """Deterministic hash of the active secret detector configuration.
    
    Ensures that identical rule sets and behavioral parameters yield
    identical detector identity hashes.
    """
    rule_dicts = []
    for r in sorted(rules, key=lambda x: x.rule_id):
        strat_repr = getattr(r.pattern_strategy, "pattern", str(r.pattern_strategy))
        rule_dicts.append({
            "rule_id": r.rule_id,
            "description": r.description,
            "detector_family": r.detector_family,
            "pattern_strategy": strat_repr,
            "keywords": sorted(r.keywords),
            "path_patterns": sorted(r.path_patterns),
            "excluded_path_patterns": sorted(r.excluded_path_patterns),
            "confidence": r.confidence,
            "specificity": r.specificity,
            "supporting_signals": sorted(r.supporting_signals),
            "entropy_threshold": r.entropy_threshold,
            "min_length": r.min_length,
            "max_length": r.max_length,
            "requires_supporting_context": r.requires_supporting_context,
        })
    canonical_bytes = json.dumps(
        rule_dicts,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()
