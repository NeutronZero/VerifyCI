"""Check manifest: the machine-readable contract published with a release."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Mapping

from verifyci.contracts.capabilities import Capability, validate_capabilities
from verifyci.contracts.model import Maturity, Tier
from verifyci.contracts.reason_codes import DEFECT_REASON_CODES
from verifyci.evidence.canonical import canonical_json_bytes


TOOL_VERSION = "3.1.10"
MANIFEST_SCHEMA = "verifyci.manifest/v3.1"
# The implementation is an M0 candidate.  Release validation artifacts are
# produced separately; this flag deliberately prevents the CLI from presenting
# a development build as a release-validated gate.
RELEASE_VALIDATED = False


@dataclass(frozen=True, slots=True)
class CheckSpec:
    check_id: str
    check_version: int
    tier: Tier
    maturity: Maturity
    method: str
    method_version: int
    supported_languages: tuple[str, ...]
    supported_syntax: tuple[str, ...]
    defect_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    evidence_kinds: tuple[str, ...]
    nullable_evidence: tuple[str, ...] = ()
    required_capabilities: tuple[Capability, ...] = ()
    required_toolchain: Mapping[str, str] = field(default_factory=dict)
    corpus_fingerprint: str = ""
    corpus_result: str = ""
    status: str = "provisional"
    since: str = "3.1.0"
    supersedes: str = ""
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_version": self.check_version,
            "tier": self.tier.value,
            "maturity": self.maturity.value,
            "method": self.method,
            "method_version": self.method_version,
            "supported_languages": list(self.supported_languages),
            "supported_syntax": list(self.supported_syntax),
            "defect_ids": list(self.defect_ids),
            "reason_codes": list(self.reason_codes),
            "evidence_kinds": list(self.evidence_kinds),
            "nullable_evidence": list(self.nullable_evidence),
            "required_capabilities": [c.value for c in self.required_capabilities],
            "required_toolchain": dict(self.required_toolchain),
            "corpus_fingerprint": self.corpus_fingerprint or None,
            "corpus_result": self.corpus_result or None,
            "status": self.status,
            "since": self.since,
            "supersedes": self.supersedes or None,
            "limitations": list(self.limitations),
        }


_GROUNDING = CheckSpec(
    check_id="grounding",
    check_version=1,
    tier=Tier.BLOCKING,
    maturity=Maturity.PROVISIONAL,
    method="changed-hunk entity mapping and exact policy deny_changes matching",
    method_version=1,
    supported_languages=("python", "typescript", "javascript", "text"),
    supported_syntax=("python-ast", "tree-sitter-typescript", "tree-sitter-javascript", "other-text"),
    defect_ids=("GRD-UNGROUNDED-EDIT",),
    reason_codes=("policy_prohibited",),
    evidence_kinds=("provenance",),
    required_capabilities=(Capability.ENTITY_SPANS,),
    required_toolchain={"python": ">=3.12", "git": "plumbing", "tree-sitter": ">=0.25"},
    corpus_fingerprint="sha256:d5ed391c68d5f9b4ab7ca54249412c051206f42b5dc7fff5de82f65e7d9442bb",
    status="provisional",
    limitations=(
        "Python and TS/JS entity spans are enumerated; an unmapped hunk is an explicit coverage gap.",
        "Supported module-level edits are mapped to other_text with line/byte provenance.",
    ),
)

_DELETION = CheckSpec(
    check_id="deletion",
    check_version=1,
    tier=Tier.BLOCKING,
    maturity=Maturity.PROVISIONAL,
    method="removed-symbol enumeration with head reference search",
    method_version=1,
    supported_languages=("python", "typescript", "javascript"),
    supported_syntax=("python-ast", "tree-sitter-typescript", "tree-sitter-javascript"),
    defect_ids=("DEL-REACHABLE-SYMBOL", "DEL-DANGLING-REFERENCE", "DEL-DYNAMIC-REFERENCE"),
    reason_codes=("symbol_live", "dangling_reference", "dynamic_reference_removed"),
    evidence_kinds=("reference",),
    required_capabilities=(Capability.SYMBOLS, Capability.REFERENCES),
    required_toolchain={"python": ">=3.12", "tree-sitter": ">=0.25"},
    status="provisional",
    limitations=(
        "Dynamic dispatch is reported as a coverage gap, never as a clean result.",
        "Reference discovery is repository-local and does not consult package indexes.",
    ),
)

_CONTRACT = CheckSpec(
    check_id="contract",
    check_version=1,
    tier=Tier.BLOCKING,
    maturity=Maturity.PROVISIONAL,
    method="signature/export comparison and local call-site compatibility",
    method_version=1,
    supported_languages=("python", "typescript", "javascript"),
    supported_syntax=("python-ast", "tree-sitter-typescript", "tree-sitter-javascript"),
    defect_ids=("CTR-SIGNATURE-BREAK", "CTR-EXPORT-BREAK", "CTR-CALL-INCOMPATIBLE"),
    reason_codes=("signature_break", "export_break", "call_incompatible"),
    evidence_kinds=("call_site", "reference"),
    required_capabilities=(Capability.SIGNATURE, Capability.CALLS, Capability.REFERENCES),
    required_toolchain={"python": ">=3.12", "tree-sitter": ">=0.25"},
    status="provisional",
    limitations=(
        "Call-site compatibility is local; unresolved dynamic calls are coverage gaps.",
        "Public API policy is exact/glob-based rather than an inferred package contract.",
    ),
)

_SEMANTIC = CheckSpec(
    check_id="semantic",
    check_version=1,
    tier=Tier.ADVISORY,
    maturity=Maturity.SHADOW,
    method="syntactic protected-guard/error candidate discovery; no solver proof in v3.1.10",
    method_version=1,
    supported_languages=("python",),
    supported_syntax=("python-ast",),
    defect_ids=(
        "SEM-GUARD-REMOVED",
        "SEM-GUARD-WEAKENED",
        "SEM-GUARD-INVERTED",
        "SEM-BINDING-SWAP",
        "SEM-EXCEPTION-REMOVED",
    ),
    reason_codes=(
        "guard_removed",
        "guard_weakened",
        "guard_inverted",
        "binding_swap",
        "exception_removed",
    ),
    evidence_kinds=("solver",),
    required_capabilities=(
        Capability.CFG,
        Capability.GUARDS,
        Capability.EFFECTS,
        Capability.EXCEPTIONS,
    ),
    required_toolchain={"python": ">=3.12"},
    status="shadow",
    limitations=(
        "Shadow only: results never affect the blocking verdict.",
        "No solver-backed witness is emitted in v3.1.10; configured semantic scope is reported as unresolved.",
    ),
)

_SECURITY = CheckSpec(
    check_id="security",
    check_version=1,
    tier=Tier.BLOCKING,
    maturity=Maturity.PROVISIONAL,
    method="offline secret validation, policy forbidden calls, and unresolved taint accounting",
    method_version=1,
    supported_languages=("python", "typescript", "javascript", "text"),
    supported_syntax=("python-ast", "tree-sitter-typescript", "tree-sitter-javascript", "other-text"),
    defect_ids=(
        "SEC-SECRET",
        "SEC-SECRET-TO-SINK",
        "SEC-TAINT-TO-SINK",
        "SEC-DANGEROUS-CALL",
    ),
    reason_codes=("secret_detected", "secret_to_sink", "taint_to_sink", "dangerous_call"),
    evidence_kinds=("secret_validation", "taint_path", "call_site"),
    required_capabilities=(Capability.CALLS, Capability.TAINT),
    required_toolchain={"python": ">=3.12"},
    status="provisional",
    limitations=(
        "Secret validation is offline and pattern-based; ambiguous candidates are coverage gaps.",
        "Taint analysis is intentionally fail-closed: configured taint scope without a resolved path is INCONCLUSIVE.",
    ),
)


CHECK_SPECS: dict[str, CheckSpec] = {
    spec.check_id: spec
    for spec in (_GROUNDING, _DELETION, _CONTRACT, _SEMANTIC, _SECURITY)
}
CHECK_ORDER: tuple[str, ...] = ("grounding", "deletion", "contract", "semantic", "security")


def manifest_payload() -> dict[str, Any]:
    return {
        "schema": MANIFEST_SCHEMA,
        "tool_version": TOOL_VERSION,
        "release_validated": RELEASE_VALIDATED,
        "checks": [CHECK_SPECS[check_id].to_dict() for check_id in CHECK_ORDER],
    }


def manifest_bytes() -> bytes:
    return canonical_json_bytes(manifest_payload())


def manifest_hash() -> str:
    return "sha256:" + sha256(manifest_bytes()).hexdigest()


def validate_manifest() -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for check_id in CHECK_ORDER:
        spec = CHECK_SPECS.get(check_id)
        if spec is None:
            errors.append(f"missing check spec {check_id}")
            continue
        if check_id in seen:
            errors.append(f"duplicate check id {check_id}")
        seen.add(check_id)
        if spec.tier == Tier.BLOCKING and spec.maturity == Maturity.SHADOW:
            errors.append(f"blocking check {check_id} cannot be shadow")
        if check_id == "semantic" and spec.tier != Tier.ADVISORY:
            errors.append("semantic must be advisory/shadow in v3.1.x")
        cap_errors = validate_capabilities(spec.required_capabilities)
        for err in cap_errors:
            errors.append(f"{check_id}: {err}")
        for defect_id in spec.defect_ids:
            if defect_id not in DEFECT_REASON_CODES:
                errors.append(f"{check_id}: unknown defect id {defect_id}")
            elif DEFECT_REASON_CODES[defect_id] not in spec.reason_codes:
                errors.append(f"{check_id}: defect {defect_id} reason code not declared")
    return errors


__all__ = [
    "CHECK_ORDER",
    "CHECK_SPECS",
    "CheckSpec",
    "MANIFEST_SCHEMA",
    "RELEASE_VALIDATED",
    "TOOL_VERSION",
    "manifest_bytes",
    "manifest_hash",
    "manifest_payload",
    "validate_manifest",
]
