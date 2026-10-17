"""Canonical deterministic attestation schema and digest computation."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from verifyci import __version__
from verifyci.contracts.verdict import VerificationFinding, VerificationVerdict

ATTESTATION_SCHEMA_VERSION = "1.0"
ATTESTATION_DIGEST_DOMAIN = "verifyci.attestation.v1:sha256"


def normalize_path(path: str) -> str:
    """Normalize file path to POSIX style with forward slashes and no leading ./."""
    p = path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def is_path_traversal(path: str) -> bool:
    """Check if a path attempts directory traversal or escapes the repository root."""
    if not path or "\x00" in path:
        return True
    p = path.strip()
    if p.startswith(("//", "\\\\", "/", "\\")):
        return True
    if len(p) >= 2 and p[1] == ":":
        return True
    lower = p.lower()
    if "%2e" in lower or "%2f" in lower or "%5c" in lower:
        return True
    norm = normalize_path(p)
    if norm.startswith(("/", "\\")):
        return True
    depth = 0
    for part in norm.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


def canonical_json_bytes(data: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme (JCS).

    Deterministic serialization: sorted keys, no whitespace separators,
    UTF-8 encoding without BOM, IEEE 754 float representation.
    """
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


class CanonicalAttestationPayload:
    """Deterministic attestation payload (high-performance slotted model)."""

    __slots__ = (
        "analyzer_version",
        "base_commit_sha",
        "files",
        "findings",
        "head_commit_sha",
        "policy_hash",
        "schema_version",
        "verdict",
    )

    def __init__(
        self,
        base_commit_sha: str,
        head_commit_sha: str,
        files: Sequence[str],
        policy_hash: str,
        verdict: VerificationVerdict,
        findings: Sequence[VerificationFinding],
        schema_version: str = ATTESTATION_SCHEMA_VERSION,
        analyzer_version: str | None = None,
    ) -> None:
        object.__setattr__(self, "base_commit_sha", base_commit_sha)
        object.__setattr__(self, "head_commit_sha", head_commit_sha)
        object.__setattr__(self, "files", tuple(files))
        object.__setattr__(self, "policy_hash", policy_hash)
        object.__setattr__(self, "verdict", verdict)
        object.__setattr__(self, "findings", tuple(findings))
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(
            self,
            "analyzer_version",
            analyzer_version or f"verifyci-{__version__}",
        )

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(f"CanonicalAttestationPayload is immutable; cannot modify '{name}'")

    def to_normalized_dict(self) -> dict[str, Any]:
        """Produce a normalized dictionary guaranteed to be deterministic."""
        normalized_files = sorted({normalize_path(f) for f in self.files if f})

        sorted_findings = sorted(
            [f.to_dict() for f in self.findings],
            key=lambda d: (
                normalize_path(d["file_path"]),
                d["start_line"],
                d["rule_id"],
                d["finding_id"],
            ),
        )

        return {
            "schema_version": self.schema_version,
            "analyzer_version": self.analyzer_version,
            "policy_hash": self.policy_hash,
            "input_manifest": {
                "base_commit_sha": self.base_commit_sha or "none",
                "head_commit_sha": self.head_commit_sha or "none",
                "files": normalized_files,
            },
            "deterministic_verdict": self.verdict.value,
            "findings": sorted_findings,
        }

    def canonical_bytes(self) -> bytes:
        """Serialize normalized payload to RFC 8785 canonical bytes."""
        return canonical_json_bytes(self.to_normalized_dict())

    def compute_digest(self) -> str:
        """Compute versioned domain-separated SHA-256 digest."""
        hasher = hashlib.sha256()
        domain_prefix = f"{ATTESTATION_DIGEST_DOMAIN}:".encode("utf-8")
        hasher.update(domain_prefix)
        hasher.update(self.canonical_bytes())
        return hasher.hexdigest()


class VerificationCertificate:
    """Complete verification certificate including envelope metadata and digest."""

    __slots__ = (
        "digest",
        "digest_algorithm",
        "execution_metadata",
        "payload",
        "rationale",
        "verdict",
    )

    def __init__(
        self,
        digest: str,
        digest_algorithm: str,
        verdict: VerificationVerdict,
        payload: CanonicalAttestationPayload,
        rationale: str,
        execution_metadata: Mapping[str, Any] | None = None,
    ) -> None:
        object.__setattr__(self, "digest", digest)
        object.__setattr__(self, "digest_algorithm", digest_algorithm)
        object.__setattr__(self, "verdict", verdict)
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "rationale", rationale)
        object.__setattr__(
            self,
            "execution_metadata",
            dict(execution_metadata) if execution_metadata else {},
        )

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(f"VerificationCertificate is immutable; cannot modify '{name}'")

    def to_dict(self) -> dict[str, Any]:
        """Export certificate for external consumers."""
        return {
            "digest": self.digest,
            "digest_algorithm": self.digest_algorithm,
            "verdict": self.verdict.value,
            "rationale": self.rationale,
            "attestation": self.payload.to_normalized_dict(),
            "execution_metadata": dict(self.execution_metadata),
        }
