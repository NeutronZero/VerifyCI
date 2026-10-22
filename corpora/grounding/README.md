# VerifyCI v3.1.10 — M1 Grounding Corpus

**Status: FROZEN.** This corpus establishes the authoritative ground truth for VerifyCI v3.1.10 Milestone M1 (Grounding). All labels have been independently authored and reviewed against the authoritative v3 design specification (§3, §8.4, §9, §11.2, §15, §16) prior to engine implementation.

## Layout

- `cases.jsonl`: case metadata and hand-authored expected contract results.
- `fixtures/<case-id>/base/` and `head/`: exact source bytes for each side.
- `fixtures/<case-id>/policy.toml`: authoritative base-policy fixture.
- `ORACLE_REVIEW.md`: requirements and sign-off record for independent oracle review.
- `SHA256SUMS`: byte-level digest inventory across all corpus files.

Preserve fixture bytes exactly: do not normalize CRLF, tabs, Unicode normalization, or encodings. Labels store both absolute byte offsets and UTF-8 byte-based positions as well as the spec-required line/column ranges. Entity spans, hunk mapping, and findings are separate oracle fields.

## Conformance and Freeze

All 24 test cases are validated against the schema, unique IDs, Git object integrity, policy parsing, reason code bijection, and span boundary integrity.
