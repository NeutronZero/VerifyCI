# Extraction Benchmark — samples/test-repo

## Repository
- Path: `samples/test-repo`
- Commit: N/A (local sample)
- Files: 3 Python files (`src/auth.py`, `src/database.py`, `src/app.py`),
  plus `src/util.c` and `README.md` (ingest coverage; outside scored ground truth)

## Method
- Ground truth: manual annotation of 11 entities across 3 Python files
- Scored types: FUNCTION, METHOD, CLASS only. MODULE / IMPORT / PARAMETER
  nodes are structural inventory outside this ground truth's scope and are
  reported separately (31 raw entities across the 3 files).
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)

## Results
| Metric    | Value | Target |
|-----------|-------|--------|
| Precision | 1.00  | > 0.85 |
| Recall    | 1.00  | > 0.80 |

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

## False positives
None.

## False negatives
None.

## Notes
- Small sample (11 entities). Precision/recall will decrease on larger repos.
- Reproduce: `python benchmarks/run_extraction.py` (TP=11 FP=0 FN=0 as of 2026-09).
- C extraction (`function_declarator` names, `type_identifier` structs) and
  METHOD classification (functions directly enclosed in a class body) verified
  by probe, not yet covered by a C ground-truth file.
