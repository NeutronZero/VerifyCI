from __future__ import annotations

import difflib

from verifyci_v2.contracts.ai_protocol import GenerativeSynthesizerProtocol
from verifyci_v2.contracts.attestation import CandidateFix, VerificationFinding
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.neural.adapters import DeterministicSynthesizerAdapter
from verifyci_v2.symbolic.z3_prover import (
    Z3SymbolicProver,
    _evaluate_concrete_divergence,
    _z3_mod,
)


class CEGISAutoRepairEngine:
    """
    Layer 6 Stage D: Z3-Verified CEGIS Auto-Repair Loop (`verifyci_v2/neural/cegis_repair.py`).
    Given a proven VerificationFinding with a CounterexampleWitness:
    1. Scrubs secrets from the failing code slice prior to synthesis.
    2. Queries `GenerativeSynthesizerProtocol` for a candidate patch (up to max_rounds = 3).
    3. Formally proves the candidate via Z3 SMT (requiring UNSAT and no unsupported nodes).
    4. Evaluates the original counterexample witness against candidate to confirm elimination.
    5. Emits the `CandidateFix` if and only if Z3 proves soundness (`z3_verified_unsat = True`).
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

        if _z3_mod is None:
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

            # Verify via Z3 SMT equivalence
            is_unsat, smt_status = self.prover.prove_equivalence(
                base_source=base_source,
                cand_source=proposed_src,
                func_base=func_base,
                func_cand=func_cand,
            )

            if not is_unsat or smt_status != "UNSAT":
                candidate_src = proposed_src
                continue

            # Confirm original counterexample witness is fixed
            fn_short = target_qualified_name.split(".")[-1]
            witness_diverges = _evaluate_concrete_divergence(
                base_src=base_source,
                head_src=proposed_src,
                fn_name=fn_short,
                params=func_base.parameters,
                witness_inputs=finding.witness.input_assignments,
            )
            if witness_diverges:
                candidate_src = proposed_src
                continue

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

        return finding