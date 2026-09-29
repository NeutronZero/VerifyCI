# Extraction Benchmark — samples/test-repo

## Repository
- Path: `samples/test-repo`
- Commit: N/A (local sample)
- Files: 3 Python files (`src/auth.py`, `src/database.py`, `src/app.py`),
  `src/util.c`, and `README.md` (ingest coverage; only scored files below
  carry ground truth)

## Method
- Ground truth: manual annotation of 13 entities (11 Python + 2 C)
- Scored types: FUNCTION, METHOD, CLASS only. MODULE / IMPORT / PARAMETER /
  TYPE nodes are structural inventory outside this ground truth's scope and
  are reported separately (39 raw entities across 4 scored files; 38 before
  C `#include` entities were extracted).
- Reproduce: `python benchmarks/run_extraction.py`

## Results
| Metric    | Value | Target |
|-----------|-------|--------|
| Precision | 1.00  | > 0.85 |
| Recall    | 1.00  | > 0.80 |

```
Results: TP=13 FP=0 FN=0
Precision: 1.00
Recall: 1.00
```
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)

## Ground Truth
| File | Entity | Type |
|------|--------|------|
| src/auth.py | authenticate | FUNCTION |
| src/auth.py | logout | FUNCTION |
| src/auth.py | AuthService | CLASS |
| src/auth.py | login | METHOD |
| src/auth.py | validate_token | METHOD |
| src/database.py | connect | FUNCTION |
| src/database.py | query | FUNCTION |
| src/database.py | Database | CLASS |
| src/database.py | __init__ | METHOD |
| src/database.py | execute | METHOD |
| src/app.py | main | FUNCTION |
| src/util.c | check_auth | FUNCTION |
| src/util.c | add | FUNCTION |

## False positives
None.

## False negatives
None.

## Notes
- Small sample (13 entities across 4 files). Precision/recall will decrease
  on larger repos.
- Reproduce: `python benchmarks/run_extraction.py` (TP=13 FP=0 FN=0).
- C extraction (`function_declarator` names, `type_identifier` structs) and
  METHOD classification (functions directly enclosed in a class body) are
  covered by the `src/util.c` ground-truth rows above.
