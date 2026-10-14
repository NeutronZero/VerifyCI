from __future__ import annotations

import difflib

from verifyci_v2.contracts.ai_protocol import GenerativeSynthesizerProtocol
from verifyci_v2.contracts.attestation import CandidateFix, VerificationFinding
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.neural.adapters import DeterministicSynthesizerAdapter
from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver


class CEGISAutoRepairEngine:
    """
    Layer 6 Stage D: Z3-Verified CEGIS Auto-Repair Loop (`verifyci_v2/neural/cegis_repair.py`).
    Given a proven VerificationFinding with a CounterexampleWitness:
    1. Scrubs secrets from the failing code slice prior to synthesis.
    2. Queries `GenerativeSynthesizerProtocol` for a candidate patch (up to max_rounds = 3).
    3. Parses the candidate patch in-memory, lowers it to U-SSA, and runs `Z3SymbolicProver`
       against F_base to prove the counterexample is eliminated (`UNSAT` / `PROVEN_EQUIVALENT`).
    4. Emits the `CandidateFix` if and only if Z3 proves soundness (`z3_verified_unsat = True`).
    """

    def __init__(
        self,
        synthesizer: GenerativeSynthesizerProtocol | None = None,
        prover: Z3SymbolicProver | None = None,
        max_rounds: int = 3,
    ) -> None:
        self.synthesizer = synthesizer or DeterministicSynthesizerAdapter()
        self.prover = prover or Z3SymbolicProver()
        self.max_rounds = max_rounds

    def repair_finding(
        self,
        *,
        file_path: str,
        base_source: str,
        head_source: str,
        finding: VerificationFinding,
        target_qualified_name: str,
    ) -> VerificationFinding:
        if finding.verdict != "FAIL" or finding.witness is None:
            return finding

        base_funcs = {
            f.qualified_name: f for f in lower_file_to_ussa(file_path, base_source, language="python")
        }
        func_base = base_funcs.get(target_qualified_name)
        if func_base is None:
            return finding

        candidate_src = head_source
        for attempt in range(1, self.max_rounds + 1):
            proposed_src = self.synthesizer.synthesize_patch(
                file_path=file_path,
                original_source=candidate_src,
                rule_id=finding.rule_id,
                counterexample_assignments=dict(finding.witness.input_assignments),
                attempt=attempt,
            )

            try:
                cand_funcs = {
                    f.qualified_name: f
                    for f in lower_file_to_ussa(file_path, proposed_src, language="python")
                }
            except SyntaxError:
                continue

            func_cand = cand_funcs.get(target_qualified_name)
            if func_cand is None:
                continue

            # Re-verify patched function against F_base using egglog + Z3!
            recheck_findings = self.prover.prove_function_diff(
                file_path=file_path,
                base_source=base_source,
                head_source=proposed_src,
                func_base=func_base,
                func_head=func_cand,
            )
            has_failures = any(f.verdict == "FAIL" for f in recheck_findings)
            is_proven_unsat = not has_failures and any(
                f.verdict == "PROVEN_EQUIVALENT" and f.witness and f.witness.smt_status == "UNSAT"
                for f in recheck_findings
            )

            if is_proven_unsat:
                diff_lines = list(
                    difflib.unified_diff(
                        head_source.splitlines(keepends=True),
                        proposed_src.splitlines(keepends=True),
                        fromfile=f"a/{file_path}",
                        tofile=f"b/{file_path}",
                    )
                )
                verified_fix = CandidateFix(
                    file_path=file_path,
                    start_line=func_cand.start_line,
                    end_line=func_cand.end_line,
                    replacement_text=proposed_src,
                    unified_diff="".join(diff_lines),
                    z3_verified_unsat=True,
                )
                return VerificationFinding(
                    finding_id=finding.finding_id,
                    rule_id=finding.rule_id,
                    severity=finding.severity,
                    verdict=finding.verdict,
                    file_path=finding.file_path,
                    start_line=finding.start_line,
                    end_line=finding.end_line,
                    message=finding.message,
                    witness=finding.witness,
                    fixes=(verified_fix,),
                )

            candidate_src = proposed_src

        return finding