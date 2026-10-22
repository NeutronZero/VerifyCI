# Grounding Oracle Review Record

**Status: FROZEN.**

This corpus serves as the frozen, independent oracle for Milestone M1 Grounding according to the VerifyCI v3.1.10 specification (§3, §8.4, §9, §15, §16).

## Oracle Review Checklist

1. [x] Explicit byte spans, UTF-8 line/column ranges, stable entity identities (`module:qualname`), and hunk-to-entity / `other_text` mappings recorded for every changed hunk.
2. [x] Base and head blob identifiers computed directly from Git object store plumbing (`git hash-object`); no invented object IDs.
3. [x] Expected check outcome, coverage, reason codes, defect/finding structures, and evidence payload requirements recorded per case.
4. [x] Semantics validated against v3.1.10 spec:
   - §5 (verdict algebra)
   - §6 (coverage and check results)
   - §8.4 (`deny_changes` canonical ordering and exact symbol / path glob requirements)
   - §9 (entity mapping, fail-closed unmapped/syntax handling, and grounding contract)
   - §15 (check corpora thresholds and adversarial suites)
5. [x] Independent review confirmed without executing the engine implementation to produce labels.
6. [x] Zero hash drift, unique case IDs, valid reason codes, valid policy TOML, and span slice integrity enforced by automated CI suite (`tests/v3/test_grounding_corpus.py`).

## Review Record

- **Reviewer:** `vc-evidence-reviewer` (Independent Oracle Adjudication)
- **Base Commit:** `2dd4683e3025162ed652f7784dbb38b521bca250`
- **Scope:** 24 cases spanning Python, TypeScript, binary, text, module-level edits, Unicode/CRLF boundaries, multi-hunk edits, deny_changes paths and symbols, policy exclusions, and Git integrity errors.
- **Fail-Closed Boundary:** Syntax errors and unmapped changes produce `INCONCLUSIVE` (`Coverage.PARTIAL`), not `ERROR`. `ERROR` is strictly reserved for Git/object/provenance integrity faults.
