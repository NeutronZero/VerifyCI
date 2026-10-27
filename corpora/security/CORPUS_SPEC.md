# M4 Security Corpus Contract

**Milestone:** VerifyCI v3.1.10 M4 — Security Analysis (`SEC-*`)
**Status:** Frozen pre-implementation oracle
**Scope:** Corpus and independent data validator only. No security engine, secret scanner, or production code is changed by this freeze contribution.

## Normative outcomes

The oracle covers the declared defects from §11.6 and §16 of the v3.1.10 design specification:

- `SEC-SECRET` / `secret_detected`: validated credential material introduced in changed text. Evidence kind: `secret_validation`. Redaction requirement: 1.0 (strict 100% redaction in findings and evidence payloads).
- `SEC-SECRET-TO-SINK` / `secret_to_sink`: validated secret flows to a log, network, serialization, or persistence sink. Evidence kind: `taint_path`.
- `SEC-TAINT-TO-SINK` / `taint_to_sink`: untrusted input reaches a policy-defined dangerous sink. Evidence kind: `taint_path`.
- `SEC-DANGEROUS-CALL` / `dangerous_call`: exact policy-forbidden call introduced. Evidence kind: `call_site`.

Coverage limitations:
- Ambiguous secret candidates yield `INCONCLUSIVE` with `Coverage.PARTIAL` (`secret_candidate_ambiguous`).
- Unresolved taint source/sink candidates yield `INCONCLUSIVE` with `Coverage.PARTIAL` (`taint_path_unresolved`).
- Relevant security edits in an unsupported language scope yield `INCONCLUSIVE` with `Coverage.UNKNOWN` (`unsupported_language`).
- Uncertainty must not be treated as `PASS`.

## Witness and evidence taxonomy

Finding witnesses conform to §11.6:
- `secret_validation`: coordinate of credential material, offline pattern/format evidence, and strict redacted representation.
- `call_site`: concrete call site introducing built-in dangerous calls (`eval`, `exec`, `os.system`, `subprocess`, `innerHTML`) or policy-forbidden custom calls.
- `taint_path`: source-to-sink flow evidence with line-level step coordinates and edge justifications.

## Candidate corpus

There are 18 frozen cases:

1. `SEC-001` (`aws_access_key`): AWS access key introduced -> `FAIL`, `SEC-SECRET` / `secret_detected`.
2. `SEC-002` (`github_token`): GitHub personal access token introduced -> `FAIL`, `SEC-SECRET` / `secret_detected`.
3. `SEC-003` (`slack_token`): Slack bot token introduced -> `FAIL`, `SEC-SECRET` / `secret_detected`.
4. `SEC-004` (`stripe_live_key`): Stripe live secret key introduced -> `FAIL`, `SEC-SECRET` / `secret_detected`.
5. `SEC-005` (`openai_api_key`): OpenAI API key introduced -> `FAIL`, `SEC-SECRET` / `secret_detected`.
6. `SEC-006` (`google_api_key`): Google Cloud API key introduced -> `FAIL`, `SEC-SECRET` / `secret_detected`.
7. `SEC-007` (`pem_private_key`): RSA private key block introduced -> `FAIL`, `SEC-SECRET` / `secret_detected`.
8. `SEC-008` (`jwt_token`): Valid structural JWT token introduced -> `FAIL`, `SEC-SECRET` / `secret_detected`.
9. `SEC-009` (`uri_credential`): Database URI containing credentials introduced -> `FAIL`, `SEC-SECRET` / `secret_detected`.
10. `SEC-010` (`generic_high_entropy`): High-entropy credential variable assignment -> `FAIL`, `SEC-SECRET` / `secret_detected`.
11. `SEC-011` (`placeholder_secret_clean`): Well-known placeholder / dummy secret value -> `PASS`, `Coverage.COMPLETE`.
12. `SEC-012` (`allowlisted_path_clean`): Key placed in policy-allowlisted fixture path -> `PASS`, `Coverage.COMPLETE`.
13. `SEC-013` (`no_text_changes_not_applicable`): Binary-only change without changed text files -> `NOT_APPLICABLE`, `Coverage.COMPLETE`.
14. `SEC-014` (`builtin_dangerous_call_eval`): Introduction of `eval` call -> `FAIL`, `SEC-DANGEROUS-CALL` / `dangerous_call`.
15. `SEC-015` (`policy_forbidden_custom_call`): Introduction of policy-forbidden call -> `FAIL`, `SEC-DANGEROUS-CALL` / `dangerous_call`.
16. `SEC-016` (`same_line_taint_to_sink`): Untrusted request parameter passed to database query -> `FAIL`, `SEC-TAINT-TO-SINK` / `taint_to_sink`.
17. `SEC-017` (`unresolved_taint_source_gap`): Untrusted source introduced without resolved flow to sink -> `INCONCLUSIVE`, `Coverage.PARTIAL` (`taint_path_unresolved`).
18. `SEC-018` (`unsupported_language_taint_scope`): Relevant change in unsupported language (Go) under configured taint policy -> `INCONCLUSIVE`, `Coverage.UNKNOWN` (`unsupported_language`).

## Independent validator scope

The independent validator (`tests/v3/test_security_corpus.py`):
1. Uses Python standard library only (`ast`, `hashlib`, `json`, `pathlib`, `re`) + `pytest`.
2. Validates `SHA256SUMS` inventory across `cases.jsonl`, `CORPUS_SPEC.md`, and `ORACLE_REVIEW.md`.
3. Verifies Python AST syntax in non-binary fixture sources.
4. Validates line numbers and witness coordinate tokens.
5. Verifies fail-closed outcome mappings, coverage categories, and defect/reason-code bijection.
6. Enforces strict Redaction 1.0 (no raw secret tokens exposed in finding messages or payloads).

## Explicit limits

This is a finite, hand-authored corpus. Conformance against this frozen suite is not a general program security or whole-program soundness guarantee. Full security sub-analysis and benchmark execution are validated separately by the production engine under test. Release qualification remains separate from implementation CI.
