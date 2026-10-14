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
    If uncalibrated, |C(x)| != 1 (ambiguous or empty), or C(x) contains any defect label != safe_label,
    VerifyCI abstains from the neural shortcut and escalates the diff to egglog + Z3 SMT.
    """
    top_choice = max(class_probabilities.items(), key=lambda kv: kv[1])[0]
    raw_prob = float(class_probabilities[top_choice])

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
    escalate = abstained or (prediction_set[0] != safe_label)

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
) -> ConformalProfile:
    """
    Runs `vc2 calibrate` over a held-out labeled dataset.
    Requires at least MIN_CALIBRATION_SAMPLES (30) to produce a calibrated profile.
    """
    is_calibrated = len(labeled_examples) >= MIN_CALIBRATION_SAMPLES

    scores: list[float] = []
    for state, true_label in labeled_examples:
        choice = judge.judge_choice(
            state=state,
            question="Classify the semantic category of this code artifact:",
            options=options,
        )
        if true_label != "none":
            # Conformal Risk Control on defect examples: risk is p(safe)
            p_safe = choice.distribution.get("none", 0.0)
            scores.append(1.0 - p_safe)
        else:
            prob_true = choice.distribution.get(true_label, 0.0)
            scores.append(1.0 - prob_true)

    q_hat = compute_conformal_quantile(scores, alpha=alpha) if scores else 1.0
    att = judge.attestation()
    return ConformalProfile(
        model_id=judge.model_id,
        weights_or_endpoint_hash=att.weights_or_endpoint_hash,
        alpha=alpha,
        sample_size=len(labeled_examples),
        q_hat=q_hat,
        is_calibrated=is_calibrated,
    )


def conformal_profile_digest(profile: ConformalProfile) -> str:
    return canonical_digest(profile, domain="verifyci.v2.conformal")