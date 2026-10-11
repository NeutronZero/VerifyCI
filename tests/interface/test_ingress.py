"""Unit tests for centralized ingress validation.

Verifies that size limits, parameter ranges, and error codes are uniformly enforced
across every caller surface.
"""
import pytest

from verifyci.interface.ingress import (
    IngressValidationError,
    validate_diff_ingress,
    validate_query_ingress,
    validate_task_ingress,
)
from verifyci.interface.limits import (
    MAX_DIFF_CHARS,
    MAX_K,
    MAX_QUERY_CHARS,
    MAX_TASK_DIFF_CHARS,
)


def test_validate_diff_ingress_valid():
    diff = "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-1\n+2\n"
    assert validate_diff_ingress(diff) == diff


def test_validate_diff_ingress_oversized():
    huge = "a" * (MAX_DIFF_CHARS + 1)
    with pytest.raises(IngressValidationError) as exc:
        validate_diff_ingress(huge)
    assert exc.value.code == "diff_too_large"


def test_validate_diff_ingress_wrong_type():
    with pytest.raises(IngressValidationError) as exc:
        validate_diff_ingress(123)  # type: ignore
    assert exc.value.code == "invalid_type"


def test_validate_task_ingress_valid():
    task, diff = validate_task_ingress("check task", diff="small diff")
    assert task == "check task"
    assert diff == "small diff"


def test_validate_task_ingress_oversized_task():
    huge_task = "t" * (MAX_TASK_DIFF_CHARS + 1)
    with pytest.raises(IngressValidationError) as exc:
        validate_task_ingress(huge_task)
    assert exc.value.code == "task_too_large"


def test_validate_task_ingress_oversized_diff():
    huge_diff = "d" * (MAX_TASK_DIFF_CHARS + 1)
    with pytest.raises(IngressValidationError) as exc:
        validate_task_ingress("t", diff=huge_diff)
    assert exc.value.code == "diff_too_large"


def test_validate_query_ingress_valid():
    q, k = validate_query_ingress("search symbol", k=5)
    assert q == "search symbol"
    assert k == 5


def test_validate_query_ingress_bounds():
    huge_q = "q" * (MAX_QUERY_CHARS + 1)
    with pytest.raises(IngressValidationError) as exc:
        validate_query_ingress(huge_q)
    assert exc.value.code == "query_too_large"

    with pytest.raises(IngressValidationError) as exc:
        validate_query_ingress("q", k=0)
    assert exc.value.code == "invalid_k"

    with pytest.raises(IngressValidationError) as exc:
        validate_query_ingress("q", k=MAX_K + 1)
    assert exc.value.code == "invalid_k"
