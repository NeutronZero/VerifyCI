# VerifyCI release evidence

Release evidence is stored at `evidence/release/<check-id>/` and committed with the
candidate release. The repository ignores generated evidence by default, with this
release-evidence subtree explicitly included for version control.

## Promotion chain

For a check to move above `shadow`, the check spec must include a target corpus,
independent held-out corpus, mined-set identity, and pinned toolchain fingerprint.
The artifacts are created in this order:

1. Freeze the candidate spec with `maturity: shadow` and calculate its
   `spec_core_hash`.
2. Run the independent measurement pipeline and save `release_report.json`.
3. Save `promotion_record.json`, hashing the exact report bytes.
4. Set the spec maturity and `promotion_record_hash`, which hashes the exact record
   bytes.

The manifest validator verifies the record, report, spec-core binding, target
maturity, toolchain fingerprint, all declared file hashes, and each required
requirement result. Missing or malformed evidence fails closed. Shadow checks must
not reference a promotion record.

## Report contract

`release_report.json` uses schema `verifyci.release_report/v1` and contains:

- `check_id`, `spec_core_hash`, `target_maturity`, and `toolchain_fingerprint`;
- `measurement_command` with non-empty `name`, `version`, and `identity`;
- `inputs` with spec-matching `corpus_hash`, `heldout_corpus_hash`, and
  `mined_corpus_id`, plus `mined_snapshot_hash`, `adjudication_hash`, and `files`;
- exactly one hashed file entry for each role `authored_corpus`, `heldout_corpus`,
  `mined_set`, and `adjudication`; each entry has repository-relative `path`,
  `sha256`, and `role`;
- a `requirements` object in which every result has `passed: true`.
- `participants` with unique non-empty `check_authors`, `heldout_labellers`, and
  `adjudicators` lists; held-out labellers and adjudicators must not overlap authors.

The currently enforced requirement IDs are `corpus_thresholds`,
`heldout_second_labeller`, `zero_false_blocking`, `coverage_agreement`,
`witness_replay`, `redaction`, `mined_conclusive_rate`, `cache_parity`,
`deterministic_payload`, and `performance_targets`.

`promotion_record.json` uses schema `verifyci.promotion_record/v1` and contains
`spec_core_hash`, `target_maturity`, `report_hash`, `toolchain_fingerprint`, and
`created_date` (`YYYY-MM-DD`). Neither artifact refers to the manifest, avoiding a
hash cycle.

## Current status

The current v3.1.10 checkout has no independent held-out/mined/adjudication
measurements or promotion records. All checks remain shadow, and the §15.10
measurement pipeline is not implemented. `scripts/validate_release.py` is only a
fail-closed manifest preflight; it does not run measurements or generate release
artifacts.
