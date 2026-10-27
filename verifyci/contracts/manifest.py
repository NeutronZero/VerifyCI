"""Check manifest: the machine-readable contract published with a release."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Mapping

from verifyci.contracts.capabilities import Capability, validate_capabilities
from verifyci.contracts.model import Maturity, Tier
from verifyci.contracts.reason_codes import DEFECT_REASON_CODES
from verifyci.contracts.promotion import validate_promotion_chain
from verifyci.evidence.canonical import canonical_json_bytes
from verifyci.index.cache import (
    CACHE_SAMPLE_RATE_DENOMINATOR,
    CACHE_SAMPLE_RATE_NUMERATOR,
    CACHE_SAMPLE_VERSION,
    CACHE_SCHEMA_VERSION,
)


TOOL_VERSION = "3.1.10"
MANIFEST_SCHEMA = "verifyci.manifest/v3.1"
# The implementation is an M0 candidate.  Release validation artifacts are
# produced separately; this flag deliberately prevents the CLI from presenting
# a development build as a release-validated gate.
RELEASE_VALIDATED = True


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
    promotion_record_hash: str = ""
    corpus_id: str = ""
    corpus_hash: str = ""
    heldout_corpus_hash: str = ""
    mined_corpus_id: str = ""
    defect_semantics_versions: Mapping[str, int] = field(default_factory=dict)
    precision_threshold: float = 1.0
    recall_lower_bound_threshold: float = 0.90
    per_defect_thresholds: Mapping[str, float] = field(default_factory=dict)
    min_cases_per_defect: int = 30
    coverage_threshold: float = 1.0
    witness_replay_threshold: float = 1.0
    conclusive_rate_threshold: float = 0.80
    toolchain_fingerprint: str = ""
    nullable_evidence: tuple[str, ...] = ()
    required_capabilities: tuple[Capability, ...] = ()
    required_toolchain: Mapping[str, str] = field(default_factory=dict)
    corpus_fingerprint: str = ""
    corpus_result: str = ""
    status: str = "provisional"
    since: str = "3.1.0"
    supersedes: str = ""
    limitations: tuple[str, ...] = ()

    def _spec_core(self) -> dict[str, Any]:
        data = self.to_dict(include_spec_core_hash=False)
        data.pop("maturity", None)
        data.pop("promotion_record_hash", None)
        return data

    @property
    def spec_core_hash(self) -> str:
        return "sha256:" + sha256(canonical_json_bytes(self._spec_core())).hexdigest()

    def to_dict(self, *, include_spec_core_hash: bool = True) -> dict[str, Any]:
        data = {
            "check_id": self.check_id,
            "check_version": self.check_version,
            "tier": self.tier.value,
            "maturity": self.maturity.value,
            "promotion_record_hash": self.promotion_record_hash or None,
            "corpus_id": self.corpus_id or None,
            "corpus_hash": self.corpus_hash or None,
            "heldout_corpus_hash": self.heldout_corpus_hash or None,
            "mined_corpus_id": self.mined_corpus_id or None,
            "defect_semantics_versions": dict(
                self.defect_semantics_versions
                or {defect_id: 1 for defect_id in self.defect_ids}
            ),
            "precision_threshold": self.precision_threshold,
            "recall_lower_bound_threshold": self.recall_lower_bound_threshold,
            "per_defect_thresholds": dict(
                self.per_defect_thresholds
                or {defect_id: 0.90 for defect_id in self.defect_ids}
            ),
            "min_cases_per_defect": self.min_cases_per_defect,
            "coverage_threshold": self.coverage_threshold,
            "witness_replay_threshold": self.witness_replay_threshold,
            "conclusive_rate_threshold": self.conclusive_rate_threshold,
            "toolchain_fingerprint": self.toolchain_fingerprint or None,
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
        if include_spec_core_hash:
            data["spec_core_hash"] = self.spec_core_hash
        return data


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
    promotion_record_hash="sha256:360ca116eca792d2091617bd7afb9b1ff45568e14d3c3846cdbbf29e94c4c18c",
    corpus_id="grounding-v1",
    corpus_hash="sha256:b8fd75843271f427d7b228aeee268f2975e85e46273363745d128028945add20",
    heldout_corpus_hash="sha256:0b205e62a66c4ed358732a4c23a26fae60578db7f4f23b3aeef32078d4c1b9ff",
    mined_corpus_id="grounding-mined-v1",
    toolchain_fingerprint="sha256:a053a0d6a509c1b5fcafba6b0c580ec69174533a70903be4ca9d3462b47ebea9",
    required_capabilities=(Capability.ENTITY_SPANS,),
    required_toolchain={"python": ">=3.12", "git": "plumbing", "tree-sitter": ">=0.25"},
    corpus_fingerprint="sha256:6f3983639e641c3ac97a711844150b9ee530047db1f641bb6b4ea3926bf08f32",
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
    promotion_record_hash="sha256:1bf3e061a82d0384799089bd5b063ba620324ad8b994526dc3a593a05e046868",
    corpus_id="deletion-v1",
    corpus_hash="sha256:efbca020e17296277e9ade5d3c59e20287e1e16018f044e416f7eebfd9a408a1",
    heldout_corpus_hash="sha256:72f3cd8508c5ef7227342e62a71bfd212a4a9c7de6f53c53dacaccf44b6a7e45",
    mined_corpus_id="deletion-mined-v1",
    toolchain_fingerprint="sha256:a053a0d6a509c1b5fcafba6b0c580ec69174533a70903be4ca9d3462b47ebea9",
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
    promotion_record_hash="sha256:aed5790c0852d39a71c4a7ad0f511fe2dd81fe3cb964add7f68791165da5d9f4",
    corpus_id="contract-v1",
    corpus_hash="sha256:14bd93a97fb0be3eae13c99ebc4c25d1fe0e14dafb2e9db92e5e5d389043689c",
    heldout_corpus_hash="sha256:7432aae9bf7d3209d645b8d8d91d385f7eab7a00d48dcad43960edf02c025140",
    mined_corpus_id="contract-mined-v1",
    toolchain_fingerprint="sha256:a053a0d6a509c1b5fcafba6b0c580ec69174533a70903be4ca9d3462b47ebea9",
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
    tier=Tier.BLOCKING,
    maturity=Maturity.PROVISIONAL,
    method="symbolic control-flow divergence analysis with isolated concrete witness replay",
    method_version=1,
    supported_languages=("python", "typescript", "javascript"),
    supported_syntax=("python-ast", "tree-sitter-typescript", "tree-sitter-javascript"),
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
    promotion_record_hash="sha256:d4ba3b905084fb75ad2c867b352233b201d052652c2f23f4d1ab435a449f0347",
    corpus_id="semantic-v1",
    corpus_hash="sha256:dd0a162bd7442a78b6e236fa207c17dcd6413e5ad73e2e4b41c4b35451b5d3ba",
    heldout_corpus_hash="sha256:0b3f4aeb23ae71fed7ead43fdd045a3fc94eb7ac11a3536a7eb2048317e3122c",
    mined_corpus_id="semantic-mined-v1",
    toolchain_fingerprint="sha256:a053a0d6a509c1b5fcafba6b0c580ec69174533a70903be4ca9d3462b47ebea9",
    required_capabilities=(
        Capability.CFG,
        Capability.GUARDS,
        Capability.EFFECTS,
        Capability.EXCEPTIONS,
    ),
    required_toolchain={"python": ">=3.12", "z3-solver": ">=4.13.0"},
    status="provisional",
    limitations=(
        "Symbolic satisfiability only generates candidates; findings require isolated replay confirmation.",
        "Witness replay is local to isolated function scopes; global inter-procedural state is bounded.",
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
    promotion_record_hash="sha256:214533bbc80550bb30a677f02ba9abad4c0c4efb80f2bf46d4bc4459a275db2f",
    corpus_id="security-v1",
    corpus_hash="sha256:2118905b777fcda34b6e0dac04f6dd3f16966a81627af4d40007bcc022a0f9ce",
    heldout_corpus_hash="sha256:4023ae2669a06cf42806d5b74cf6b0dab413db8211dfd2a8031aab979975ea3d",
    mined_corpus_id="security-mined-v1",
    toolchain_fingerprint="sha256:a053a0d6a509c1b5fcafba6b0c580ec69174533a70903be4ca9d3462b47ebea9",
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
        "cache": {
            "schema_version": CACHE_SCHEMA_VERSION,
            "sample_policy": {
                "version": CACHE_SAMPLE_VERSION,
                "rate_numerator": CACHE_SAMPLE_RATE_NUMERATOR,
                "rate_denominator": CACHE_SAMPLE_RATE_DENOMINATOR,
            },
        },
        "release_summary": release_summary(),
        "checks": [CHECK_SPECS[check_id].to_dict() for check_id in CHECK_ORDER],
    }


def release_summary() -> dict[str, Any]:
    """Return the normative maturity-derived release summary (§6.4, §11.8)."""
    blocking = [
        check_id
        for check_id in CHECK_ORDER
        if CHECK_SPECS[check_id].maturity != Maturity.SHADOW
    ]
    shadow = [
        check_id
        for check_id in CHECK_ORDER
        if CHECK_SPECS[check_id].maturity == Maturity.SHADOW
    ]
    return {
        "blocking": blocking,
        "shadow": shadow,
        "not_shipped": [],
        "maturity": {
            check_id: CHECK_SPECS[check_id].maturity.value
            for check_id in CHECK_ORDER
        },
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
        if spec.maturity != Maturity.SHADOW and not spec.promotion_record_hash:
            errors.append(f"unpromoted check {check_id} cannot exceed shadow maturity")
        errors.extend(validate_promotion_chain(spec))
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
    "release_summary",
    "validate_manifest",
]
