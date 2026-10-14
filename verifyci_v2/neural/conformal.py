from __future__ import annotations

import math
from typing import Sequence

from verifyci_v2.contracts.ai_protocol import (
    CalibratedDecision,
    ConformalProfile,
    DiscriminativeJudgeProtocol,
)
from verifyci_v2.contracts.canonical import canonical_digest

MIN_CALIBRATION_SAMPLES: int = 30


def compute_conformal_quantile(
    non_conformity_scores: Sequence[float],
    alpha: float = 0.02,
) -> float:
    """
    Computes the finite-sample Split Conformal Prediction quantile q_hat for target error rate alpha:
    q_hat = Quantile({R_1, ..., R_n, inf}, ceil((n + 1)(1 - alpha)) / n)
    Guarantees P(y_true in C(x_new)) >= 1 - alpha regardless of underlying model calibration.
    """
    if not (0.0 < alpha < 1.0):
        raise ValueError("Target false-pass error rate alpha must be in (0, 1)")
    n = len(non_conformity_scores)
    if n == 0:
        return 1.0
    sorted_scores = sorted(float(s) for s in non_conformity_scores)
    rank = math.ceil((n + 1) * (1.0 - alpha))
    if rank > n:
        return 1.0
    return round(sorted_scores[rank - 1], 6)


def evaluate_with_conformal_gate(
    class_probabilities: dict[str, float],
    profile: ConformalProfile,
    safe_label: str = "none",
) -> CalibratedDecision:
    """
    Constructs the conformal prediction set C(x) = {y : 1 - p(y|x) <= q_hat}.
    Enforces statistically valid selective risk control for the critical event:
    'a defective change is accepted as safe'.
    If:
      1. Profile is uncalibrated, OR
      2. tau_safe > 1.0 (indicating confident misclassifications on calibration defects or small sample), OR
      3. p(safe) < tau_safe, OR
      4. Prediction set C(x) is not the singleton {safe_label},
    VerifyCI abstains from the neural shortcut and escalates to egglog + Z3 SMT (fail-closed).
    """
    top_choice = max(class_probabilities.items(), key=lambda kv: kv[1])[0]
    raw_prob = float(class_probabilities[top_choice])
    p_safe = float(class_probabilities.get(safe_label, 0.0))

    if not getattr(profile, "is_calibrated", True):
        return CalibratedDecision(
            prediction_set=tuple(sorted(class_probabilities.keys())),
            top_choice=top_choice,
            raw_probability=round(raw_prob, 6),
            abstained=True,
            escalate_to_smt=True,
        )

    prediction_set = tuple(
        label
        for label, prob in sorted(class_probabilities.items())
        if (1.0 - float(prob)) <= profile.q_hat + 1e-9
    )

    abstained = len(prediction_set) != 1
    tau_safe = getattr(profile, "tau_safe", 1.0)
    cleared_risk = (tau_safe <= 1.0) and (p_safe >= tau_safe)

    escalate = abstained or (prediction_set != (safe_label,)) or not cleared_risk

    return CalibratedDecision(
        prediction_set=prediction_set,
        top_choice=top_choice,
        raw_probability=round(raw_prob, 6),
        abstained=abstained,
        escalate_to_smt=escalate,
    )


def calibrate_judge_on_dataset(
    judge: DiscriminativeJudgeProtocol,
    labeled_examples: Sequence[tuple[dict[str, str], str]],
    options: Sequence[str],
    *,
    alpha: float = 0.02,
    safe_label: str = "none",
) -> ConformalProfile:
    """
    Runs calibration over a held-out labeled dataset.
    Requires at least MIN_CALIBRATION_SAMPLES (30) to produce a calibrated profile.
    Separates general calibration scores from defect false-pass risk scores:
      1. General non-conformity score: 1.0 - p(y_true)
      2. Defect false-pass score for y != safe: p(safe)
         Controls P(accepted as safe | defect) <= alpha by setting tau_safe.
         If any defect is confidently misclassified (high p(safe)), tau_safe exceeds 1.0,
         failing closed to 100% SMT escalation.
    """
    is_calibrated = len(labeled_examples) >= MIN_CALIBRATION_SAMPLES

    general_scores: list[float] = []
    defect_safe_probs: list[float] = []

    for state, true_label in labeled_examples:
        choice = judge.judge_choice(
            state=state,
            question="Classify the semantic category of this code artifact:",
            options=options,
        )
        dist = choice.distribution
        prob_true = dist.get(true_label, 0.0)
        general_scores.append(1.0 - prob_true)

        if true_label != safe_label:
            p_safe_on_defect = dist.get(safe_label, 0.0)
            defect_safe_probs.append(p_safe_on_defect)

    q_hat = compute_conformal_quantile(general_scores, alpha=alpha) if general_scores else 1.0

    m = len(defect_safe_probs)
    if not is_calibrated or m < 10:
        tau_safe = 2.0
    else:
        sorted_defect_probs = sorted(defect_safe_probs)
        rank = math.ceil((m + 1) * (1.0 - alpha))
        if rank > m:
            tau_safe = 2.0
        else:
            val_at_rank = sorted_defect_probs[rank - 1]
            if val_at_rank >= 0.5:
                tau_safe = 2.0
            else:
                tau_safe = round(val_at_rank + 1e-4, 6)

    att = judge.attestation()
    return ConformalProfile(
        model_id=judge.model_id,
        weights_or_endpoint_hash=att.weights_or_endpoint_hash,
        alpha=alpha,
        sample_size=len(labeled_examples),
        q_hat=q_hat,
        is_calibrated=is_calibrated,
        tau_safe=tau_safe,
        defect_sample_size=m,
    )


def conformal_profile_digest(profile: ConformalProfile) -> str:
    return canonical_digest(profile, domain="verifyci.v2.conformal")