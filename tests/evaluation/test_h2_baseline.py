"""H2 final measured baseline (reconciled at final landing, see notes).

History, preserved not overwritten:
- H2-A pre-intervention (frozen reference): 16/18, 1.0, 1.0 (exact).
- H2-B isolated measurement: 17/18, 1.0, 1.0 (relative-import
  residual recovered, no precision loss).
- Final combined B+C measurement
  (benchmarks/invariants/h2_measure.py, frozen labels reverified):
  18/18, 1.0, 1.0 (short-secret residual recovered, no precision
  loss). This file asserts the FINAL state. B and C were never
  measured combined before the final pass.
"""
from tests.evaluation.test_labeled_ground_truth_v2 import load_v2_cases
from verifyci.verification.intent_align import score_labeled

# Pre-intervention: 16/18. Post-H2-B: 17/18. Final (B+C): 18/18.
MEASURED_RECALL = 18 / 18
MEASURED_PRECISION = 1.0
MEASURED_COVERAGE = 1.0


def test_h2_final_measured_baseline():
    metrics = score_labeled(load_v2_cases())
    assert metrics.check_coverage == MEASURED_COVERAGE
    assert metrics.detection_recall == MEASURED_RECALL
    assert metrics.detection_precision == MEASURED_PRECISION
