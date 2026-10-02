from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class VerificationPlan:
    plan_id: str
    checks: list["VerificationCheck"]
    thresholds: dict[str, float]
    blockers: list[str]
    intent_package_id: str


@dataclass(frozen=True)
class VerificationCheck:
    check_id: str
    type: str
    target: str
    parameters: dict[str, Any]
    blocking: bool


@dataclass(frozen=True)
class Certificate:
    '''
    certificate_verified is True if and only if:
    - all deterministic checks passed and checked_by non-empty
    - execution traces non-empty
    - evidence non-empty
    - conclusion result is pass
    '''
    certificate_id: str
    premises: list["Premise"]
    evidence: list["FileEvidence"]
    execution_traces: list["ExecutionTrace"]
    conclusion: "Conclusion"
    confidence: float
    generated_by: str
    checked_by: list[str]
    verification_method: str
    certificate_verified: bool
    timestamp: float


@dataclass(frozen=True)
class Premise:
    premise_id: str
    statement: str
    source: str


@dataclass(frozen=True)
class FileEvidence:
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    source_hash: str


@dataclass(frozen=True)
class ExecutionTrace:
    trace_id: str
    path: list[str]
    conditions: list[str]
    """Control-flow guards under which the path is taken. Reserved for the
    V1.1 CFG/DFG; V1 AST-derived CPG has no guard edges, so producers leave
    this empty rather than filling it with traversal metadata."""


@dataclass(frozen=True)
class Conclusion:
    result: str
    reasoning: str


@dataclass(frozen=True)
class BlastRadiusResult:
    affected_callers: list[str]
    affected_callees: list[str]
    test_coverage_gap: list[str]
    risk_score: float
    dependency_impact: list[str]
    vulnerability_impact: list[str]


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    passed: bool
    score: float
    evidence: list[str]
    explanation: str
    blocking: bool = True
    certificate: Optional[Certificate] = None
    deterministic: bool = True  # False for LLM-opinion checks (policy ignores them)
    established: bool = True  # False when the check ran against nothing
    # (e.g. zero relevant edges): inability, not rejection. Policy routes
    # established blocking failures to FAIL and unestablished ones to
    # INCONCLUSIVE — a pass-on-zero-edges is a different verdict from a
    # pass-on-500-edges, recorded here rather than in prose.


@dataclass(frozen=True)
class VerificationReport:
    report_id: str
    task_id: str
    policy_id: str
    checks: list[CheckResult]
    blast_radius: BlastRadiusResult
    timestamp: float


@dataclass(frozen=True)
class VerificationPolicy:
    policy_id: str
    on_failure: str
    on_inconclusive: str
    on_human_review: str
    require_deterministic_checker: bool


@dataclass(frozen=True)
class VerificationDecision:
    decision_id: str
    report_id: str
    status: str
    policy_id: str
    rationale: str
    timestamp: float


@dataclass(frozen=True)
class InvariantMetrics:
    check_coverage: float
    detection_recall: Optional[float] = None
    detection_precision: Optional[float] = None
    """Recall/precision are None when unmeasured (no labeled ground truth).
    None renders as null in JSON — deliberately distinct from 0.0, which
    would read as "measured and terrible". """


@dataclass(frozen=True)
class Invariant:
    invariant_id: str
    rule: str
    compiled_query: str
    blocking: bool


@dataclass(frozen=True)
class IntentPackage:
    intent_package_id: str
    specs: list[dict[str, Any]]
    invariants: list[Invariant]
    nfrs: list[dict[str, Any]]
    verification_plan_id: str
